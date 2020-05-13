/*
 *  This is an example of a function that can detect strings known at compile
 *  time.
 */
static inline bool python3(char const *str)
{
    char needle[] = "/usr/bin/python3";
    char haystack[sizeof(needle)];
    bpf_probe_read_str(&haystack, sizeof(haystack), (void *)str);
    for (int i = 0; i < sizeof(needle); ++i)
    {
        if (needle[i] != haystack[i])
        {
            return false;
        }
    }
    return true;
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
//RAW_TRACEPOINT_PROBE(sched_process_exec)
//{
//    u32 pid = bpf_get_current_pid_tgid();
//
//    /* Yoink the linux_binprm */
//    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
//
//    /* Figure out if we are in webserver.py */
//    char interp[40];
//    bpf_probe_read_str(interp, sizeof(interp), bprm->interp);
//
//    if (python3(interp))
//    {
//        bpf_trace_printk("Interpreter %s!\n", bprm->interp);
//        bpf_trace_printk("Filename %s!\n", bprm->filename);
//    }
//
//    /* Create / look up process */
//    // TODO
//
//    return 0;
//}
