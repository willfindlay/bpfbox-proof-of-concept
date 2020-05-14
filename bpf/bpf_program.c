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

/*
 * TODO: In the future, we will determine our profile based on what binary /
 * script is running.
 *
 * The problem is that I'm not sure about the best way to extract that sort of
 * information for interpretted files, such as webserver.py. Depending on how
 * the file is run, we either have a (file, interp) pair of (python3, webserver.py)
 * or (python3, python3). The former case is trivial, but the latter case
 * causes problems.
 *
 * For this proof of concept, we won't worry about any of this, and instead
 * elect to pass the webserver's PID via a command line argument. */
RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    // Check pid and create state for process if we are in the right process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_state *state;
    if (pid == THE_PID)
        state = create_or_lookup_bpfbox_state(pid);
    else
        state = states.lookup(&pid);

    if (!state)
        return 0;

    /* Yoink the linux_binprm */
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
    struct dentry *dentry = bprm->file->f_path.dentry;
    struct dentry *parent = bprm->file->f_path.dentry->d_parent;
    u32 inode = dentry->d_inode->i_ino;
    u32 parent_inode = parent ? parent->d_inode->i_ino : 0;

    // The following actually actually shouldn't be necessary
    // since we are already enforcing execution in do_filp_open

    //if (state->tainted)
    //{
    //    bpf_trace_printk("hello executing world!\n");
    //    if (FS_EXEC_RULES)
    //        return 0;
    //    else
    //        bpf_send_signal(SIGKILL);
    //}

    return 0;
}

/* Probe every fork/vfork/clone and duplicate the current
 * bpfbox state, including taintedness. */
RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct bpfbox_state *state;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;

    state = states.lookup(&ppid);
    if (!state)
        return 0;

    states.update(&cpid, state);

    return 0;
}

/* A kprobe that checks the arguments to do_filp_open
 * (underlying implementation of open, openat, and openat2). */
int kprobe__do_filp_open(struct pt_regs *ctx, int dfd,
        struct filename *pathname, const struct open_flags *op)
{
    // Check pid and lookup state if it exists
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_state *state = states.lookup(&pid);
    if (!state)
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
    // Check pid and lookup state if it exists
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_state *state = states.lookup(&pid);
    if (!state)
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

    // If we are not tainted we don't care
    if (!state->tainted)
    {
        return 0;
    }

    struct dentry *dentry = fp->f_path.dentry;
    struct dentry *parent = fp->f_path.dentry->d_parent;
    u32 inode = dentry->d_inode->i_ino;
    u32 parent_inode = parent ? parent->d_inode->i_ino : 0;
    int acc_mode = op->acc_mode;

    if (acc_mode & MAY_WRITE)
    {
        bpf_trace_printk("hello writing world!\n");
        if (FS_WRITE_RULES)
            return 0;
        else
            bpf_send_signal(SIGKILL);
    }

    if (acc_mode & MAY_READ)
    {
        bpf_trace_printk("hello reading world!\n");
        if (FS_READ_RULES)
            return 0;
        else
            bpf_send_signal(SIGKILL);
    }

    if (acc_mode & MAY_APPEND)
    {
        bpf_trace_printk("hello appending world!\n");
        if (FS_APPEND_RULES)
            return 0;
        else
            bpf_send_signal(SIGKILL);
    }

    if (acc_mode & MAY_EXEC)
    {
        bpf_trace_printk("hello executing world!\n");
        if (FS_EXEC_RULES)
            return 0;
        else
            bpf_send_signal(SIGKILL);
    }

    bpf_trace_printk("enforcing on %s!\n", dentry->d_name.name);

    bpf_send_signal(SIGKILL);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind)
{
    // Check pid and lookup state if it exists
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_state *state = states.lookup(&pid);
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
