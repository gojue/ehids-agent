#include "ehids_agent.h"

//辅助Map索引
#define CWD_BUF_IDX                     0
#define PATH_BUF_IDX                    1
#define STRING_BUF_IDX                  2

#define MAX_DEPTH                       10
#define UTS_MAX_LEN                     64
#define PATH_MAX_LEN                    256
#define TASK_COMM_LEN                   16
#define MAX_STRING_SIZE                 256
#define BUF_SIZE_MAP_NS                 256
#define MAX_PERCPU_BUFSIZE              (1 << 12)

#define MAX_PATH_COMPONENTS 20

#define my_bpf_printk(fmt, ...)					\
	do {							\
		char s[] = fmt;					\
		bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__);	\
	} while (0)

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })


struct buf_t {
    u8 buf[MAX_PERCPU_BUFSIZE];
} ;

// bufs map
struct {
       __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct buf_t);
        __uint(max_entries, 3);
} bufs SEC(".maps");

struct {
       __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, u64);
        __type(value, struct bpf_context_t);
        __uint(max_entries, 2048);
} bpf_context SEC(".maps");

struct {
       __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, u32);
        __type(value, struct bpf_context_t);
        __uint(max_entries, 1);
} bpf_context_gen SEC(".maps");

struct {
       __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//        __type(key, int);
//        __type(value, __u32);
        __uint(max_entries, 4);
//        __uint(pinning, LIBBPF_PIN_NONE);
} events SEC(".maps");

/*============================ HELPER FUNCTIONS ==============================*/
static __always_inline struct buf_t* get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

/*================ KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/
static __always_inline u32 internal_get_task_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

static __always_inline u32 internal_get_task_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

    struct pid *tpid = READ_KERN(task->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
    return nr;
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

    struct pid *tpid = READ_KERN(group_leader->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);

    return nr;
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace* uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

static __always_inline u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_euid(struct task_struct *task)
{
    struct cred *cred = (struct cred *)READ_KERN(task->real_cred);
    return READ_KERN(cred->euid.val);
}

static __always_inline u32 get_task_gid(struct task_struct *task)
{
    struct cred *cred = (struct cred *)READ_KERN(task->real_cred);
    return READ_KERN(cred->gid.val);
}

static __always_inline u32 get_task_egid(struct task_struct *task)
{
    struct cred *cred = (struct cred *)READ_KERN(task->real_cred);
    return READ_KERN(cred->egid.val);
}

static __always_inline u64 get_task_start_time(struct task_struct *task)
{
    return READ_KERN(task->start_time);
}

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static __always_inline struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline void get_proc_cmdline(struct task_struct *task, char *cmdline, int size)
{
    struct mm_struct *mm = READ_KERN(task->mm);
    long unsigned int args_start = READ_KERN(mm->arg_start);
    long unsigned int args_end = READ_KERN(mm->arg_end);
    int len = (args_end - args_start);
    if (len >= size)
        len = size - 1;
    bpf_probe_read(cmdline, len & (size - 1), (const void *)args_start);
}


/*=============================== KERNEL STRUCTS =============================*/
struct syscall_bpf_args {
    unsigned long long unused;
    long syscall_nr;
    int cmd;
    union bpf_attr* uattr;
    unsigned int size;
};

/*=============================== INTERNAL STRUCTS ===========================*/
struct proc_common
{
    __u32 pid;
    __u32 tgid;
    __u32 nspid;
    __u32 nstgid;
    __u32 ppid;
    __u32 ptgid;
    __u32 nsppid;
    __u32 nsptgid;
    __u32 pppid;
    __u32 pptgid;
    __u32 nspppid;
    __u32 nspptgid;
    __u32 uid;
    __u32 euid;
    __u32 gid;
    __u32 egid;
    __u32 uts_inum;
    __u32 pending;
    __u64 start_time;
    __u8 comm[TASK_COMM_LEN];
    __u8 cmdline[PATH_MAX_LEN];
    __u8 uts_name[UTS_MAX_LEN];
};

struct bpf_context_t
{
    __u32 cmd;
    __u32 pending;
    struct proc_common procinfo;
};

/*============================ HELPER FUNCTIONS ==============================*/

static __always_inline void print_debug(struct proc_common *procinfo)
{
#if 1
    my_bpf_printk("\n pid:  %d\n tgid:  %d\n nspid:  %d\n", procinfo->pid, procinfo->tgid, procinfo->nspid);
    my_bpf_printk("\n nstgid:  %d\n ppid:  %d\n ptgid:  %d\n", procinfo->nstgid, procinfo->ppid, procinfo->ptgid);
    my_bpf_printk("\n nsppid:  %d\n nsptgid:  %d\n pppid:  %d\n", procinfo->nsppid, procinfo->nsptgid, procinfo->pppid);
    my_bpf_printk("\n pptgid:  %d\n nspppid:  %d\n nspptgid:  %d\n", procinfo->pptgid, procinfo->nspppid, procinfo->nspptgid);
    my_bpf_printk("\n comm:  %s\n ", procinfo->comm);
    my_bpf_printk("\n cmdline:  %s\n", procinfo->cmdline);
    my_bpf_printk("\n start_time:  %ld\n", procinfo->start_time);
    my_bpf_printk("\n uid:  %d\n euid:  %d\n gid:  %d\n", procinfo->uid, procinfo->euid, procinfo->gid);
    my_bpf_printk("\n egid:  %d\n uts_name:  %s\n uts_ium:  %u\n", procinfo->egid, procinfo->uts_name, procinfo->uts_inum);
    my_bpf_printk("*********** \n");
#endif
}

static __always_inline void get_common_proc(struct proc_common *procinfo)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    //process
    procinfo->pid = internal_get_task_pid(task);
    procinfo->tgid = internal_get_task_tgid(task);
    procinfo->nspid = get_task_ns_pid(task);
    procinfo->nstgid = get_task_ns_tgid(task);
    procinfo->uid = bpf_get_current_uid_gid();
    procinfo->euid = get_task_euid(task);
    procinfo->gid = get_task_gid(task);
    procinfo->egid = get_task_egid(task);
    procinfo->start_time = get_task_start_time(task);
    procinfo->uts_inum = get_task_uts_ns_id(task);
    //parent process
    procinfo->ppid = internal_get_task_pid(READ_KERN(task->real_parent));
    procinfo->ptgid = internal_get_task_tgid(READ_KERN(task->real_parent));
    procinfo->nsppid = get_task_ns_pid(READ_KERN(task->real_parent));
    procinfo->nsptgid = get_task_ns_tgid(READ_KERN(task->real_parent));
    //parent parent process
    struct task_struct *parent = READ_KERN(task->real_parent);
    procinfo->pppid = internal_get_task_pid(READ_KERN(parent->real_parent));
    procinfo->pptgid = internal_get_task_tgid(READ_KERN(parent->real_parent));
    procinfo->nspppid = get_task_ns_pid(READ_KERN(parent->real_parent));
    procinfo->nspptgid = get_task_ns_tgid(READ_KERN(parent->real_parent));
    bpf_get_current_comm(procinfo->comm, 16);

    char * uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(procinfo->uts_name, sizeof(procinfo->uts_name), uts_name);

    get_proc_cmdline(task, procinfo->cmdline, sizeof(procinfo->cmdline));

	print_debug(procinfo);
}

//这个函数用来规避512字节栈空间限制，通过在堆上创建内存的方式，避开限制
static __always_inline struct bpf_context_t *make_event() {
    u32 key_gen = 0;
    struct bpf_context_t *bpf_ctx = bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx)
        return 0;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}

static __always_inline void send_event(void *ctx, struct bpf_context_t *context)
{
    // send event
    u64 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &events, cpu, context, sizeof(struct bpf_context_t));
    return;
}

/*============================== SYSCALL HOOKS ===============================*/

SEC("tracepoint/syscalls/sys_enter_bpf")
int tracepoint_sys_enter_bpf(struct syscall_bpf_args *args) {
	struct bpf_context_t *bpf_context = make_event();
	if (!bpf_context)
		return 0;
	bpf_context->cmd = args->cmd;
	get_common_proc(&bpf_context->procinfo);
	send_event(args, bpf_context);
    return 0;
}