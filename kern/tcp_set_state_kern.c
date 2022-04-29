#include "ehids_agent.h"

#define F_OUTBOUND 0x1
#define F_CONNECTED 0x10
#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10
struct event_t
{
    u64 start_ns;   //启动时间
    u64 end_ns;
    u32 pid;
    u32 laddr;
    u16 lport;
    u32 raddr;
    u16 rport;
    u8 flags;
    u64 rx_b;
    u64 tx_b;
    char task[TASK_COMM_LEN];
    u16 family;
    u32 uid;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct conn_t
{
    u32 pid;
    u64 start_ns;
    u8 flags;
    char task[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock *);
    __type(value, struct conn_t);
    __uint(max_entries, 10240);
} conns SEC(".maps");

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    if (!sk)
        return 0;

    int state = (int)PT_REGS_PARM2(ctx);

    struct conn_t *pconn;
    pconn = bpf_map_lookup_elem(&conns, &sk);

    struct conn_t conn = {};

    if (state == TCP_SYN_SENT)
    {
        // this is the first state of OUTBOUND connection
        if (pconn)
        {
            bpf_map_delete_elem(&conns, &sk);
        }

        //create temp conn
        conn.flags = F_OUTBOUND;
        conn.start_ns = bpf_ktime_get_ns();

        goto attach_pid_and_update_conn;
    }

    if (!pconn)
    {
        if (state == TCP_ESTABLISHED)
        {
            // this is the first state of INBOUND connection

            // create conn
            conn.flags |= F_CONNECTED;
            conn.start_ns = bpf_ktime_get_ns();

            goto update_conn;
        }

        // missed creation
        return 0;
    }

    bpf_probe_read(&conn, sizeof(conn), pconn);

    if (state == TCP_ESTABLISHED)
    {
        // successful outbound connection
        conn.flags |= F_CONNECTED;
        goto update_conn;
    }

    if (state == TCP_LAST_ACK)
        goto attach_pid_and_update_conn;

    if (state != TCP_CLOSE)
        return 0;

    // NOTE: we do filter here at TCP_CLOSE state
    // NOTE: accept IPv4 only
    struct event_t data = {};

    bpf_probe_read(&data.family, sizeof(data.family), &sk->__sk_common.skc_family);
    if (data.family != AF_INET)
        goto delete_conn;

    bpf_probe_read(&data.laddr, sizeof(data.laddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&data.raddr, sizeof(data.raddr), &sk->__sk_common.skc_daddr);

    // NOTE: ignore local <-> local
    if ((data.laddr & 0xff) == 0x7f && (data.raddr & 0xff) == 0x7f)
        goto delete_conn;

    bpf_probe_read(&data.lport, sizeof(data.lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&data.rport, sizeof(data.rport), &sk->__sk_common.skc_dport);

    data.start_ns = conn.start_ns;
    data.end_ns = bpf_ktime_get_ns();
    data.pid = conn.pid;
    u32 uid = bpf_get_current_uid_gid();
    data.uid = uid;
    __builtin_memcpy(&data.task, &conn.task, sizeof(data.task));

    data.flags = conn.flags;
    data.rport = (u16)(data.rport);

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    bpf_probe_read(&data.rx_b, sizeof(data.rx_b), &tp->bytes_received);
    bpf_probe_read(&data.tx_b, sizeof(data.tx_b), &tp->bytes_acked);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

delete_conn:
    bpf_map_delete_elem(&conns, &sk);
    return 0;

attach_pid_and_update_conn:
    bpf_get_current_comm(&conn.task, sizeof(conn.task));
    conn.pid = bpf_get_current_pid_tgid() >> 32;

update_conn:
    bpf_map_update_elem(&conns, &sk, &conn, BPF_ANY);
    return 0;
}