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


struct Stats {
    unsigned long long recv_bytes_window = 0;
    unsigned long long sent_bytes_window = 0;
    char comm[16]; // nombre del proceso
};

static std::map<int, Stats> process_BW;
static unsigned long long window_start_ts = 0;
const unsigned long long WINDOW_NS = 5ull * 1000000000ull; // ventana de 5 segundos


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

static void print_bandwidth(unsigned long long now_ts) {
    double elapsed_sec = (now_ts - window_start_ts) / 1e9;

    printf("\n=== Ventana de %.2f segundos ===\n", elapsed_sec);
    for (auto &kv : process_BW) {
        int pid = kv.first;
        Stats &s = kv.second;
        double in_rate = s.recv_bytes_window / elapsed_sec;
        double out_rate = s.sent_bytes_window / elapsed_sec;

        printf("PID=%d  COMM=%s  RECV=%.2f B/s  SENT=%.2f B/s  (Total %llu IN, %llu OUT)\n",
               pid, s.comm, in_rate, out_rate,
               s.recv_bytes_window, s.sent_bytes_window);
    }
    printf("=================================\n\n");

    // resetear stats
    process_BW.clear();
    window_start_ts = now_ts;
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

static void print_process(net_event* e, ProcStats &st,std::string key) {


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
    std::string iface=getActiveInterfaceName();
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



static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
   struct net_event *e = (struct net_event *) data;

    
    char keybuf[64];
    snprintf(keybuf, sizeof(keybuf), "%s:%d", e->comm, e->pid);
    std::string key(keybuf);

    if (proc_table.find(key) == proc_table.end()) {
        proc_table[key] = {0, 0, 0, 0, 0};
    }

    auto &st = proc_table[key];


    //print_process(e,st,key);

    


        //ancho de banda
    if (window_start_ts == 0)
            window_start_ts = e->ts;

        // Acumular bytes por proceso
        Stats &bw = process_BW[e->pid];
        bw.comm[sizeof(bw.comm)-1] = '\0'; // asegurar terminador
        strncpy(bw.comm, e->comm, sizeof(bw.comm)-1);

        if (e->direction == 0) {
            bw.recv_bytes_window += e->bytes;
        } else {
            bw.sent_bytes_window += e->bytes;
        }

        // Revisar si se venció la ventana
        if (e->ts - window_start_ts >= WINDOW_NS) {
            print_bandwidth(e->ts);
        }
    

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
