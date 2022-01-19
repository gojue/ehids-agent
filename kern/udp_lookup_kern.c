#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// https://datatracker.ietf.org/doc/html/draft-ietf-dnsind-udp-size
// max udp size for DNS
#define MAX_PKT 512
#define TASK_COMM_LEN 16

struct dns_data_t
{
    u32 pid;
    char comm[TASK_COMM_LEN]; // TODO: for debug, remove pls
    u8 pkt[MAX_PKT];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_events SEC(".maps");

typedef struct msghdr *hihi;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct msghdr *);
    __uint(max_entries, 10240);
} tbl_udp_msg_hdr SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dns_data_t);
    __uint(max_entries, 1);
} dns_data SEC(".maps");

// https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c#L1834
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)(ctx)->di; // sock

    // NOTE: verifier raises bug when dereference sk
    // https://github.com/iovisor/bcc/issues/253
    // https://github.com/iovisor/bcc/issues/1858
    u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    // only grab port 53 packets, 13568 is ntohs(53)
    if (dport == 13568)
    {
        struct msghdr *msg = (struct msghdr *)(ctx)->si;
        bpf_map_update_elem(&tbl_udp_msg_hdr, &pid_tgid, &msg, BPF_ANY);
    }
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int trace_ret_udp_recvmsg(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct msghdr **msgpp = bpf_map_lookup_elem(&tbl_udp_msg_hdr, &pid_tgid);
    if (msgpp == 0)
        return 0;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;

    struct iov_iter iter = {};

    bpf_probe_read(&iter, sizeof(iter), &msghdr->msg_iter);
    if (iter.type != ITER_IOVEC)
        goto delete_and_return;

    int copied = (int)(ctx)->ax;
    if (copied < 0 || copied > MAX_PKT)
        // dns packet < 512 bytes
        goto delete_and_return;

    // bpf_printk("len: %d\n", copied);

    u32 buflen = (u32)copied;
    if (buflen > MAX_PKT)
        // NOTE: not sure but verifier complained without this
        buflen = (u32)MAX_PKT;

    buflen = buflen & 0x1ff;
    
    struct iovec iov;
    bpf_probe_read(&iov, sizeof(iov), iter.iov);
    if (buflen > iov.iov_len)
        goto delete_and_return;

    u32 zero = 0;
    struct dns_data_t *data = bpf_map_lookup_elem(&dns_data, &zero);
    if (!data)
        // this should never happen, just making the verifier happy
        return 0;

    // TODO: remove this
    if (bpf_get_current_comm(data->comm, sizeof(data->comm)) != 0)
        goto delete_and_return;

    bpf_probe_read(data->pkt, buflen, iov.iov_base);

    data->pid = pid_tgid >> 32;

    bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, data, 4 + 16 + buflen);

    // 55: (85) call bpf_probe_read#4 R2 min value is negative, either use unsigned or 'var &= const'
    //相同案例 https://lists.iovisor.org/g/iovisor-dev/topic/30315706
delete_and_return:
    bpf_map_delete_elem(&tbl_udp_msg_hdr, &pid_tgid);
    return 0;
}

char __license[] SEC("license") = "GPL";