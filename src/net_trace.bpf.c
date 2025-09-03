#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct net_event {
    __u64 ts;
    __u32 pid;
    char comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 bytes;
    __u8  direction; // 0=recv,1=send
    __u8  protocol;  // 6=TCP,17=UDP
    char ifname[16]; // nombre de la interfaz
    __u32 ifindex;
};

// Mapa tipo perf buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Helper para llenar datos de TCP/UDP
static __always_inline void fill_event(struct net_event *ev, struct sock *sk,
                                       size_t size, int dir, int proto) {
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts = bpf_ktime_get_ns();
    ev->bytes = size;
    ev->direction = dir;
    ev->protocol = proto;
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    __u16 sport=0, dport=0;
    __u32 saddr=0, daddr=0, ifidx=0;

    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&ifidx, sk, __sk_common.skc_bound_dev_if);

    ev->sport = sport;
    ev->dport = __bpf_ntohs(dport);
    ev->saddr = saddr;
    ev->daddr = daddr;
    ev->ifindex = ifidx;

    ev->ifname[0] = 0; // se llenará en espacio de usuario con if_indextoname
}


// Kprobes TCP/UDP
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || size==0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, size, 1, IPPROTO_TCP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (!sk || copied<=0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, copied, 0, IPPROTO_TCP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || size==0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, size, 1, IPPROTO_UDP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || (long)size<=0) return 0;
    struct net_event ev = {};
    fill_event(&ev, sk, size, 0, IPPROTO_UDP);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// Tracepoint net_dev_queue: captura interfaz y bytes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, char[16]);
} ifnames SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    struct net_event ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.bytes = (__u64)(ctx->data_end - ctx->data);
    ev.ifindex = ctx->ingress_ifindex;

    char *name = bpf_map_lookup_elem(&ifnames, &ev.ifindex);
    if (name)
        __builtin_memcpy(ev.ifname, name, 16);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return XDP_PASS;
}