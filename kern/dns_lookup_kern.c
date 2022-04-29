#include "ehids_agent.h"

#define AF_INET 2
#define AF_INET6 10

// struct addrinfo copied from: include/netdb.h
struct addrinfo
{
  int ai_flags;         /* Input flags.  */
  int ai_family;        /* Protocol family for socket.  */
  int ai_socktype;      /* Socket type.  */
  int ai_protocol;      /* Protocol for socket.  */
  u32 ai_addrlen;       /* Length of socket address.  */ // CHANGED from socklen_t
  struct sockaddr *ai_addr; /* Socket address for socket.  */
  char *ai_canonname;       /* Canonical name for service location.  */
  struct addrinfo *ai_next; /* Pointer to next in list.  */
};

struct val_t {
    u32 pid;
    char host[80];
} __attribute__((packed));

struct data_t {
    u32 pid;
    u32 uid;
    u32 af;
    u32 ip4addr;
    __int128 ip6addr;
    char host[80];
} __attribute__((packed));

struct {
       __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, u32);
        __type(value, struct val_t);
        __uint(max_entries, 1024);
} start SEC(".maps");


struct {
       __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, u32);
        __type(value, struct addrinfo **);
        __uint(max_entries, 1024);
} currres SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/getaddrinfo")
int getaddrinfo_entry(struct pt_regs *ctx) {
    if (!(ctx)->di)
        return 0;
    struct val_t val = {};

    bpf_probe_read(&val.host, sizeof(val.host), (void *)PT_REGS_PARM1(ctx));
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    val.pid = pid;
    struct addrinfo **res = (struct addrinfo **)(ctx)->cx;
    bpf_map_update_elem(&start, &pid, &val, BPF_ANY);
    bpf_map_update_elem(&currres, &pid, &res, BPF_ANY);
    return 0;
}

SEC("uretprobe/getaddrinfo")
int getaddrinfo_return(struct pt_regs *ctx) {
    struct val_t *valp;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    valp = bpf_map_lookup_elem(&start, &pid);
    if (valp == 0) {
        return 0; // missed start
    }

    struct addrinfo ***res;
    res = bpf_map_lookup_elem(&currres, &pid);

    if (!res || !(*res)) {
        return 0;   // missed entry
    }
    u32 uid = bpf_get_current_uid_gid();
    struct addrinfo **resx;
    bpf_probe_read(&resx, sizeof(resx), (struct addrinfo **)res);
    struct addrinfo *resxx;
    bpf_probe_read(&resxx, sizeof(resxx), (struct addrinfo **)resx);

    for (int i = 0; i < 9; i++) //  Limit max entries that are considered
    {
        struct data_t data = {};
        bpf_probe_read(&data.host, sizeof(data.host), (void *)valp->host);
        bpf_probe_read(&data.af, sizeof(data.af), &resxx->ai_family);

        if (data.af == AF_INET) {
            struct sockaddr_in *daddr;
            bpf_probe_read(&daddr, sizeof(daddr), &resxx->ai_addr);
            bpf_probe_read(&data.ip4addr, sizeof(data.ip4addr), &daddr->sin_addr.s_addr);
        } else if (data.af == AF_INET6) {
            struct sockaddr_in6 *daddr6;
            bpf_probe_read(&daddr6, sizeof(daddr6), &resxx->ai_addr);
            bpf_probe_read(&data.ip6addr, sizeof(data.ip6addr), &daddr6->sin6_addr.in6_u.u6_addr32);
        }

        data.pid = valp->pid;
        data.uid = uid;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // TODO 
//        if (resxx->ai_next == NULL) {
//            break;
//        }
//        resxx = resxx->ai_next;
        break;
    }

    bpf_map_delete_elem(&start, &pid);
    bpf_map_delete_elem(&currres, &pid);
    return 0;
}