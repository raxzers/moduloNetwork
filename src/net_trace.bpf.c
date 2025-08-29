#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ---- struct para eventos ----
struct net_event {
    __u64 ts;
    __u32 pid;
    char comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 bytes;
    __u64 volume;
    __u64 bw;
    __u32 ifindex;
    __u8  direction;
    __u8  protocol;
};

// ---- clave y contexto de flujo ----
struct flow_key {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u32 ifindex;
};

struct flow_ctx {
    __u64 last_ts;
    __u64 volume;
};

// ---- mapa de flujo ----
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct flow_ctx);
} flow_stats SEC(".maps");

// ---- mapa perf buffer ----
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// ---- función auxiliar ----
static __always_inline void fill_event(struct net_event *ev, struct sock *sk,
                                       size_t len, int dir, int proto) {
    __builtin_memset(ev, 0, sizeof(*ev));
    __u64 ts = bpf_ktime_get_ns();
    ev->ts = ts;
    ev->bytes = len;
    ev->direction = dir;
    ev->protocol = proto;

    ev->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    // IP y puertos
    __u16 sport = 0, dport = 0;
    __u32 saddr = 0, daddr = 0;

    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    

    ev->sport = sport;
    ev->dport = __bpf_ntohs(dport);
    ev->saddr = saddr;
    ev->daddr = daddr;

    // ifindex
    __u32 ifindex = 0;
    BPF_CORE_READ_INTO(&ifindex, sk, __sk_common.skc_bound_dev_if);
    ev->ifindex = ifindex;

    // ---- calcular volumen acumulado y BW ----
    struct flow_key key = {};
    key.pid = ev->pid;
    key.saddr = ev->saddr;
    key.daddr = ev->daddr;
    key.sport = ev->sport;
    key.dport = ev->dport;
    key.protocol = ev->protocol;
    key.ifindex = ev->ifindex;

    struct flow_ctx *ctx, new_ctx = {};
    ctx = bpf_map_lookup_elem(&flow_stats, &key);
    if (!ctx) {
        new_ctx.last_ts = ts;
        new_ctx.volume = len;
        bpf_map_update_elem(&flow_stats, &key, &new_ctx, BPF_ANY);
        ev->volume = new_ctx.volume;
        ev->bw = 0;
    } else {
        __u64 delta = ts - ctx->last_ts;
        ctx->volume += len;
        ev->volume = ctx->volume;
        ev->bw = (delta > 0) ? (len * 1000000000ULL / delta) : 0;
        ctx->last_ts = ts;
    }
}

// ---- Hooks TCP ----
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || size == 0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, size, 1, IPPROTO_TCP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (!sk || copied <= 0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, copied, 0, IPPROTO_TCP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// ---- Hooks UDP ----
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || size == 0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, size, 1, IPPROTO_UDP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || (long)size <= 0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, size, 0, IPPROTO_UDP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}


