#include "ehids_agent.h"

//solaris/native/java/lang/childproc.h
struct jdk_execvpe {
    u32 pid;
    u64 mode;
    char file[128];
    // char argv[128];
    // char envp[128];
} __attribute__((packed));


struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} jdk_execvpe_events SEC(".maps");



// JDK_execvpe(int mode, const char *file, const char *argv[], const char *const envp[])

SEC("uprobe/JDK_execvpe")
int java_JDK_execvpe(struct pt_regs *ctx) {
    
    int *mode = (int *)PT_REGS_PARM1(ctx); //

    if (!mode) {
       return 0;   // missed entry
    }

    struct jdk_execvpe val = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    val.pid = pid;
    
    val.mode = (u64)mode;

    const char *file = (const char *)PT_REGS_PARM2(ctx); //

    if (!file) {
       return 0;   // missed entry
    }
    // bpf_probe_read_str(val.file, sizeof(val.file), file);
    bpf_probe_read_user_str(val.file, sizeof(val.file), file);

    const char (*argv)[];
    // bpf_probe_read(&resx, sizeof(resx), (struct addrinfo **)res);
    if (bpf_probe_read(&argv, sizeof(argv), (const char(*)[])PT_REGS_PARM3(ctx)) != 0) {
       return 0;   // missed entry
    }       

    bpf_perf_event_output(ctx, &jdk_execvpe_events, BPF_F_CURRENT_CPU, &val, sizeof(val));
    return 0;
}