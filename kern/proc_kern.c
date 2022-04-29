#include "ehids_agent.h"

#define MAX_DEPTH 10

#define ENABLE_FORK
#define ENABLE_EXEC
#define ENABLE_EXIT

typedef enum my_event_type_t
{
    EVENT_FORK = 1,
    EVENT_EXEC = 2,
    EVENT_EXIT = 3
} my_event_type;

typedef struct _process_info_t
{
    int type;
    pid_t child_pid;
    pid_t child_tgid;
    pid_t parent_pid;
    pid_t parent_tgid;
    
    pid_t grandparent_pid;
    pid_t grandparent_tgid;
    uid_t uid;
    gid_t gid;


    int cwd_level;
    u32 uts_inum;
    __u64 start_time;
    char comm[16];
    char cmdline[128];
    char filepath[128];
} proc_info_t;

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // need page align
} ringbuf_proc SEC(".maps");

struct sys_enter_exit_args
{
    unsigned short common_type;
    unsigned char common_flag;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int error_code;
};

struct sys_enter_fork_args
{
    unsigned short common_type;
    unsigned char common_flag;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
};

SEC("kretprobe/copy_process")
int kretprobe_copy_process(struct pt_regs *regs)
{
#ifdef ENABLE_FORK
    struct task_struct *task = (struct task_struct *)PT_REGS_RC(regs);  //copy_process 返回的是子进程 task_struct
    long ret = 0, offset = 0;
    proc_info_t *ringbuf_process;

    ringbuf_process = bpf_ringbuf_reserve(&ringbuf_proc, sizeof(proc_info_t), 0);
    if (!ringbuf_process)
        return -1;

    ringbuf_process->type = EVENT_FORK;
    ringbuf_process->child_pid = BPF_CORE_READ(task, pid);
    ringbuf_process->child_tgid = BPF_CORE_READ(task, tgid);
    unsigned int level = BPF_CORE_READ(task, thread_pid, level);    //ringbuf_process->child_nstgid = BPF_CORE_READ(task, nsproxy, pid);  //暂未获取，参考 内核task_tgid_nr_ns即可获得
    bpf_get_current_comm(ringbuf_process->comm, 16);
    long unsigned int args_start = BPF_CORE_READ(task, mm, arg_start);
    long unsigned int args_end = BPF_CORE_READ(task, mm, arg_end);
    int len = (args_end - args_start) & 0x7F;
    ret = bpf_probe_read_user(ringbuf_process->cmdline, len, (const void *)args_start);
    // for (int i = 0; i < len; i++)
    // {
    //     if (ringbuf_process->cmdline[i] == '\0')
    //         ringbuf_process->cmdline[i] = ' ';
    // }
    // ringbuf_process->cmdline[127] = '\0';
    ret = bpf_probe_read_user_str(ringbuf_process->filepath, 128, (const void *)args_start);
    ringbuf_process->parent_pid = BPF_CORE_READ(task, real_parent, pid);
    ringbuf_process->parent_tgid = BPF_CORE_READ(task, real_parent, tgid);
    unsigned int parent_level = BPF_CORE_READ(task, real_parent, thread_pid, level);

    ringbuf_process->grandparent_pid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    ringbuf_process->grandparent_tgid = BPF_CORE_READ(task, real_parent, real_parent, tgid);
    ringbuf_process->uid = BPF_CORE_READ(task, cred, uid).val;
    ringbuf_process->gid = BPF_CORE_READ(task, cred, gid).val;
    ringbuf_process->start_time = BPF_CORE_READ(task, start_time);
    ringbuf_process->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns).inum;
   
    bpf_ringbuf_submit(ringbuf_process, 0);
#endif
    return 0;
}