#include "ehids_agent.h"

#ifndef NOCORE
    // TODO
#endif

#define TASK_COMM_LEN 16
#define AF_UNIX 1
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 af;
    u32 laddr;
    u16 lport;
    u32 daddr;
    u16 dport;
    char task[TASK_COMM_LEN];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv4_events SEC(".maps");




struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u16 dport;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv6_events SEC(".maps");


struct other_socket_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} other_socket_events SEC(".maps");

SEC("kprobe/security_socket_connect")
int kprobe__security_socket_connect(struct pt_regs *ctx) {
    int ret = (ctx)->ax;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 uid = bpf_get_current_uid_gid();

    //获取sock信息
    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
    if (!skp)
        return 0;

    //获取addr信息
    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!address)
        return 0;

    u32 address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

    if (address_family == AF_INET) {
        struct ipv4_event_t data4 = {.pid = pid, .uid = uid, .af = address_family};
        data4.ts_us = bpf_ktime_get_ns() / 1000;

        struct sockaddr_in *daddr = (struct sockaddr_in *)address;


        bpf_probe_read(&data4.laddr, sizeof(data4.laddr), &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &skp->__sk_common.skc_daddr);

        bpf_probe_read(&data4.lport, sizeof(data4.lport), &skp->__sk_common.skc_num);
        bpf_probe_read(&data4.dport, sizeof(data4.dport), &skp->__sk_common.skc_dport);

        bpf_get_current_comm(&data4.task, sizeof(data4.task));


        if (data4.dport != 0) {
            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &data4, sizeof(data4));
        }
    }
    else if (address_family == AF_INET6) {
        struct ipv6_event_t data6 = {.pid = pid, .uid = uid, .af = address_family};
        data6.ts_us = bpf_ktime_get_ns() / 1000;

        struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;

        bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32);

        u16 dport6 = 0;
        bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port);
        data6.dport = (u16)(dport6);

        bpf_get_current_comm(&data6.task, sizeof(data6.task));

        if (data6.dport != 0) {
            bpf_perf_event_output(ctx, &ipv6_events, BPF_F_CURRENT_CPU, &data6, sizeof(data6));

        }
    }
    else if (address_family != AF_UNIX && address_family != AF_UNSPEC) { // other sockets, except UNIX and UNSPEC sockets
        struct other_socket_event_t socket_event = {.pid = pid, .uid = uid, .af = address_family};
        socket_event.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        bpf_perf_event_output(ctx, &other_socket_events, BPF_F_CURRENT_CPU, &socket_event, sizeof(socket_event));
    }

    return 0;
}