// SPDX-License-Identifier: MIT
// Arch Forward Observations System - eBPF Network Flow Attribution (US-16)

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2

// Stable UAPI tracepoint layout for sock/inet_sock_set_state
struct trace_event_raw_inet_sock_set_state {
    __u64 unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct flow_event {
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 protocol;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} FLOW_EVENTS SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (!ctx)
        return 0;

    // Emit on outbound connect initiation (SYN_SENT) or established connections
    if (ctx->newstate != TCP_SYN_SENT && ctx->newstate != TCP_ESTABLISHED)
        return 0;

    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;

    struct flow_event *ev = bpf_ringbuf_reserve(&FLOW_EVENTS, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = (__u32)(pid_tgid >> 32);
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->family = ctx->family;
    ev->protocol = ctx->protocol ? ctx->protocol : IPPROTO_TCP;
    ev->sport = ctx->sport;
    ev->dport = ctx->dport;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    __builtin_memset(ev->saddr, 0, sizeof(ev->saddr));
    __builtin_memset(ev->daddr, 0, sizeof(ev->daddr));

    if (ctx->family == AF_INET) {
        __builtin_memcpy(ev->saddr, ctx->saddr, 4);
        __builtin_memcpy(ev->daddr, ctx->daddr, 4);
    } else {
        __builtin_memcpy(ev->saddr, ctx->saddr_v6, 16);
        __builtin_memcpy(ev->daddr, ctx->daddr_v6, 16);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// UDP outbound capture via cgroup/sendmsg4 (attached when cgroup v2 is available)
SEC("cgroup/sendmsg4")
int handle_udp_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (!ctx || ctx->protocol != 17) // IPPROTO_UDP
        return 1;

    struct flow_event *ev = bpf_ringbuf_reserve(&FLOW_EVENTS, sizeof(*ev), 0);
    if (!ev)
        return 1;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = (__u32)(pid_tgid >> 32);
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->family = AF_INET;
    ev->protocol = 17;
    ev->sport = 0;
    ev->dport = __builtin_bswap16((__u16)(ctx->user_port & 0xffff));
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    __builtin_memset(ev->saddr, 0, sizeof(ev->saddr));
    __builtin_memset(ev->daddr, 0, sizeof(ev->daddr));
    __u32 daddr = ctx->user_ip4;
    __builtin_memcpy(ev->daddr, &daddr, 4);

    bpf_ringbuf_submit(ev, 0);
    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
