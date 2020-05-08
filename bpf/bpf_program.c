#include <linux/binfmts.h>

typedef struct
{
    u8 tainted;
}
bprm_state;

static int bpf_strncmp(char *s1, char *s2, u32 n)
{
    int mismatch = 0;
    for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];

        if (s1[i] == s2[i] == '\0')
            return 0;
    }

    return 0;
}

static int bpf_strcmp(char *s1, char *s2)
{
    u32 s1_size = sizeof(s1);
    u32 s2_size = sizeof(s2);

    return bpf_strncmp(s1, s2, s1_size < s2_size ? s1_size : s2_size);
}

RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    u32 pid = bpf_get_current_pid_tgid();

    /* Yoink the linux_binprm */
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    /* Figure out if we are in webserver.py */
    // TODO

    /* Create / look up process */
    // TODO

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!bpf_strcmp(comm, "ls"))
        bpf_trace_printk("ls!\n");

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    return 0;
}
