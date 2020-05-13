#include <linux/binfmts.h>
// TODO: select correct unistd based on architecture
// (via a build flag from userspace)
#include <uapi/asm/unistd_64.h>

typedef struct
{
    u8 tainted;
}
bpfbox_state;

BPF_HASH(states, u32, bpfbox_state);

static bpfbox_state *create_or_lookup_bpfbox_state(u32 pid)
{
    bpfbox_state temp = {
        .tainted = 0,
    };
    return state.lookup_or_try_init(&pid, &temp);
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    long syscall = args->id;

    // Check PID
    if (pid != THE_PID)
        return 0;

    // Create or lookup bpfbox_state
    bpfbox_state *state = create_or_lookup_bpfbox_state(pid);
    if (!state)
        return 0;

    // Apply taint rule
    if (syscall == __NR_)

    // Enforce policy if we are tainted
    if (state->tained)
    {

    }

    bpf_trace_printk("Hello webserver %d!\n", args->id);

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
