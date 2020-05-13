// binfmt (not needed for proof of concept, but needed for final version)
#include <linux/binfmts.h>

// socketaddr struct
#include <linux/socket.h>

// open, openat, openat2 flags
#include <uapi/linux/fcntl.h>
#include <linux/fs.h>
// FIXME: why can't we find this header file?
// fs/internal.h
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

// system call numbers
// TODO: select correct unistd based on architecture
// (via a build flag from userspace)
#include <uapi/asm/unistd_64.h>

struct bpfbox_state
{
    u8 tainted;
};

BPF_HASH(states, u32, struct bpfbox_state);

BPF_PERCPU_ARRAY(do_filp_open_intermediate, struct open_flags, 1);

static struct bpfbox_state *create_or_lookup_bpfbox_state(u32 pid)
{
    struct bpfbox_state temp = {
        .tainted = 0,
    };
    return states.lookup_or_try_init(&pid, &temp);
}

/* A kprobe that checks the arguments to do_filp_open
 * (underlying implementation of open, openat, and openat2). */
int kprobe__do_filp_open(struct pt_regs *ctx, int dfd,
        struct filename *pathname, const struct open_flags *op)
{
    // Check pid
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != THE_PID)
        return 0;

    int zero = 0;
    struct open_flags tmp;
    bpf_probe_read(&tmp, sizeof(tmp), op);

    do_filp_open_intermediate.update(&zero, &tmp);

    return 0;
}

/* A kretprobe that checks the file struct pointer returned
 * by do_filp_open (underlying implementation of open, openat,
 * and openat2). */
int kretprobe__do_filp_open(struct pt_regs *ctx)
{
    // Check pid
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != THE_PID)
        return 0;

    // Yoink file pointer from retuen value
    struct file *fp = (struct file*)PT_REGS_RC(ctx);
    if (!fp)
    {
        return 0;
    }

    // Access the open_flags struct from the entrypoint arguments
    int zero = 0;
    struct open_flags *op = do_filp_open_intermediate.lookup(&zero);
    if (!op)
    {
        return 0;
    }

    // Create or lookup bpfbox_state
    struct bpfbox_state *state = create_or_lookup_bpfbox_state(pid);
    if (!state)
        return 0;

    // If we are not tainted we don't care
    if (!state->tainted)
    {
        return 0;
    }

    struct dentry *dentry = fp->f_path.dentry;
    struct dentry *parent = fp->f_path.dentry->d_parent;

    u32 inode = dentry->d_inode->i_ino;
    u32 parent_inode = parent ? parent->d_inode->i_ino : 0;
    umode_t mode = op->mode;

    bpf_trace_printk("mode %d\n", mode);

    if ((mode & O_ACCMODE) == O_WRONLY)
    {
        bpf_trace_printk("hello writing world!\n");
        if (FS_WRITE_RULES)
            return 0;
    }

    if ((mode & O_ACCMODE) == O_RDONLY)
    {
        bpf_trace_printk("hello reading world!\n");
        if (FS_READ_RULES)
            return 0;
    }

    if ((mode & O_ACCMODE) == O_RDWR)
    {
        bpf_trace_printk("hello reading and writing world!\n");
        if (FS_READWRITE_RULES)
            return 0;
    }

    bpf_send_signal(SIGKILL);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind)
{
    // Check PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != THE_PID)
        return 0;

    // Create or lookup bpfbox_state
    struct bpfbox_state *state = create_or_lookup_bpfbox_state(pid);
    if (!state)
        return 0;

    if (!state->tainted)
    {
        // Taint rule
        struct sockaddr addr = {};
        bpf_probe_read(&addr, sizeof(addr), (void *)args->umyaddr);
        if (addr.sa_family == AF_INET)
        {
            state->tainted = 1;
            bpf_trace_printk("Detected system call bind with AF_INET, "
                    "tainting process state\n");
        }

        return 0;
    }

    // Default deny after taint
    bpf_send_signal(SIGKILL);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    long syscall = args->id;

    // Check PID
    if (pid != THE_PID)
        return 0;

    return 0;
}
