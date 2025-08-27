#include <iostream>
#include <csignal>
#include <bpf/libbpf.h>
#include "net_event.h"
#include "net_trace.skel.h"

static volatile bool running = true;

static void sig_handler(int signo) {
    running = false;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    auto *e = (struct net_event *)data;

    std::cout << "[" << e->pid << "] "
              << e->comm
              << " proto=" << (int)e->protocol
              << (e->direction ? " SEND " : " RECV ")
              << e->bytes << " bytes"
              << std::endl;
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
