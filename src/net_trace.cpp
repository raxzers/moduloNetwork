#include <iostream>
#include <csignal>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include "net_event.h"

#include "net_trace.skel.h"

static volatile bool running = true;

static void sig_handler(int signo) {
    running = false;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct net_event *e = (struct net_event *) data;

    char saddr[16], daddr[16], ifname[IF_NAMESIZE];
    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));

    // traducir ifindex → nombre de interfaz
    if_indextoname(e->ifindex, ifname);

    printf("[%llu] %-6s %-5d %-16s %-15s:%-5d -> %-15s:%-5d bytes=%llu dir=%s proto=%s iface=%s\n",
           e->ts,
           e->comm,
           e->pid,
           e->comm,
           saddr, e->sport,
           daddr, e->dport,
           e->bytes,
           e->direction ? "OUT" : "IN",
           e->protocol == IPPROTO_TCP ? "TCP" : "UDP",
           ifname[0] ? ifname : "unknown");
}


static void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
    std::cerr << "Lost " << lost_cnt << " events on CPU " << cpu << std::endl;
}

int main() {
    signal(SIGINT, sig_handler);

    struct net_trace_bpf *skel = net_trace_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open/load skeleton\n";
        return 1;
    }

    if (net_trace_bpf__attach(skel)) {
        std::cerr << "Failed to attach probes\n";
        net_trace_bpf__destroy(skel);
        return 1;
    }

    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
                                              8, handle_event, handle_lost, nullptr, nullptr);
    if (!pb) {
        std::cerr << "Failed to open perf buffer\n";
        net_trace_bpf__destroy(skel);
        return 1;
    }

    std::cout << "Tracing... Press Ctrl+C to stop\n";

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    perf_buffer__free(pb);
    net_trace_bpf__destroy(skel);
    return 0;
}
