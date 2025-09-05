#include <iostream>
#include <csignal>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unordered_map>
#include <sys/socket.h>
#include "net_event.h"
#include "net_trace.skel.h"

#include <map>
#include <string>

#include <iomanip>
#include <unistd.h>
#include <netinet/in.h>





static volatile bool running = true;

static void sig_handler(int signo) {
    running = false;
}

struct ProcStats {
    unsigned long long r_bytes;    
    unsigned long long s_bytes;    
    unsigned long long last_r_bytes;
    unsigned long long last_s_bytes;
    unsigned long long last_ts;
};

static std::map<std::string, ProcStats> proc_table;
    // Mapa global ifindex → nombre


std::string getActiveInterfaceName() {
    // 1. Creamos socket UDP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "";

    sockaddr_in remoteAddr{};
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_port = htons(53); // puerto DNS
    inet_pton(AF_INET, "8.8.8.8", &remoteAddr.sin_addr);

    if (connect(sock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr)) < 0) {
        close(sock);
        return "";
    }

    sockaddr_in localAddr{};
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sock, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        close(sock);
        return "";
    }

    close(sock);

    // 2. Mapear IP local a interfaz usando getifaddrs
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return "";

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &localAddr.sin_addr, ip, sizeof(ip));

    std::string ifaceName = "";

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;

        char addr[INET_ADDRSTRLEN];
        sockaddr_in *sa = (sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr));

        if (strcmp(addr, ip) == 0) {
            ifaceName = ifa->ifa_name;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return ifaceName;
}



static void print_summary() {
    std::cout << "\n==== Trafico acumulado por proceso ====\n";
    std::cout << std::left << std::setw(20) << "Proceso"
              << std::right << std::setw(15) << "Recv (bytes)"
              << std::setw(15) << "Sent (bytes)" << "\n";
    std::cout << "---------------------------------------------\n";

    for (auto &p : proc_table) {
        std::cout << std::left << std::setw(20) << p.first
                  << std::right << std::setw(15) << p.second.r_bytes
                  << std::setw(15) << p.second.s_bytes << "\n";
    }
}





static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
   struct net_event *e = (struct net_event *) data;

    std::string iface=    getActiveInterfaceName();
    

    char keybuf[64];
    snprintf(keybuf, sizeof(keybuf), "%s:%d", e->comm, e->pid);
    std::string key(keybuf);

    if (proc_table.find(key) == proc_table.end()) {
        proc_table[key] = {0, 0, 0, 0, 0};
    }

    auto &st = proc_table[key];

    // actualizar acumulados primero
    if (e->direction!=0)
        st.s_bytes += e->bytes;  // OUT
    else
        st.r_bytes += e->bytes;  // IN

    double r_rate = 0.0, s_rate = 0.0;

    if (st.last_ts != 0) {
        unsigned long long delta_ts = e->ts - st.last_ts;
        if (delta_ts > 0) {
            double delta_sec = delta_ts / 1e9;

            unsigned long long delta_r = st.r_bytes - st.last_r_bytes;
            unsigned long long delta_s = st.s_bytes - st.last_s_bytes;

            r_rate = delta_r / delta_sec;
            s_rate = delta_s / delta_sec;
        }
    }

    // imprimir antes de actualizar snapshots
    printf("[%llu] %-20s Recv=%llu  Sent=%llu  Rate: IN=%.2f B/us OUT=%.2f B/us (last=%llu direct=%d) proto=%s iface=%s %s:%d -> %s:%d\n",
           e->ts,
           key.c_str(),
           st.r_bytes,
           st.s_bytes,
           r_rate,
           s_rate,
           e->bytes,
           e->direction ,
           e->protocol == IPPROTO_TCP ? "TCP" : "UDP",
           iface.c_str(),
           inet_ntoa(*(struct in_addr*)&e->saddr), e->sport,
           inet_ntoa(*(struct in_addr*)&e->daddr), e->dport);

    //printf("direction=%u protocol=%u\n", e->direction, e->protocol);



    // ahora sí: actualizar snapshots
    st.last_r_bytes = st.r_bytes;
    st.last_s_bytes = st.s_bytes;
    st.last_ts      = e->ts;

    

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
    print_summary();
    perf_buffer__free(pb);
    net_trace_bpf__destroy(skel);
    return 0;
}
