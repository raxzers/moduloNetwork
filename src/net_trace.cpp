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
#include <fstream>
#include <ctime>
#include <thread>
#include <chrono>



#include <sstream>

static volatile bool running = true;

static void sig_handler(int signo) {
    running = false;
}

enum Mode { MODE_EVENTS, MODE_BANDWIDTH };
Mode mode = MODE_EVENTS;


Mode parse_mode(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "mode=bandwidth") return MODE_BANDWIDTH;
        if (arg == "mode=events") return MODE_EVENTS;
    }
    return MODE_EVENTS; // por defecto
}

struct Stats {
    unsigned long long recv_bytes_window = 0;
    unsigned long long sent_bytes_window = 0;
    char comm[16]; // nombre del proceso
};

static std::map<int, Stats> process_BW;
static unsigned long long window_start_ts = 0;



struct ProcStats {
    unsigned long long r_bytes= 0;    
    unsigned long long s_bytes= 0;    
    unsigned long long last_r_bytes= 0;
    unsigned long long last_s_bytes= 0;
    unsigned long long total_r_bytes= 0;
    unsigned long long total_s_bytes= 0;
    unsigned long long last_r_delta= 0;
    unsigned long long last_s_delta = 0;
    unsigned long long last_ts = 0;
};

std::ofstream csv_file;
bool csv_initialized = false;




void init_csv() {
    if (csv_initialized) return;

    time_t now = time(nullptr);
    struct tm *lt = localtime(&now);
    char filename[64];
    strftime(filename, sizeof(filename), "processed_data/measurements_%Y%m%d_%H%M.csv", lt);
    csv_file << std::fixed << std::setprecision(0);
    csv_file.open(filename);
    csv_file << "TIMESTAMP,PID,COMM,RECV_BYTES,SENT_BYTES,RECV_RATE,SENT_RATE,PROTOCOL,IFACE,SRC_IP,SRC_PORT,DST_IP,DST_PORT,TOTAL_RECV_BYTES,TOTAL_SENT_BYTES\n";
    csv_initialized = true;
}

static std::map<std::string, ProcStats> proc_table;
    // Mapa global ifindex → nombre

struct LastSample {
    unsigned long long ts;       // último timestamp
    unsigned long long r_bytes;  // último recibido
    unsigned long long s_bytes;  // último enviado
};

std::unordered_map<int, LastSample> last_sample;

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
        // Crear nombre de archivo con fecha/hora
    time_t now = time(nullptr);
    struct tm *lt = localtime(&now);
    std::ostringstream filename;
    filename << "processed_data/report"
             << std::put_time(lt, "%Y%m%d_%H%M")
             << ".txt";

    // Abrir archivo en modo escritura
    std::ofstream report(filename.str());
    if (!report.is_open()) {
        std::cerr << "Error al crear " << filename.str() << "\n";
        return;
    }

    // Encabezado
    std::ostringstream output;
    output << "\n==== Trafico acumulado por proceso ====\n";
    output << std::left << std::setw(20) << "Proceso"
           << std::right << std::setw(15) << "Recv (bytes)"
           << std::setw(15) << "Sent (bytes)" << "\n";
    output << "---------------------------------------------\n";

    // Cuerpo de datos
    for (auto &p : proc_table) {
        output << std::left << std::setw(20) << p.first
               << std::right << std::setw(15) << p.second.total_r_bytes
               << std::setw(15) << p.second.total_s_bytes << "\n";
    }

    // Mostrar en consola
    std::cout << output.str();

    // Escribir al archivo .txt
    report << output.str();
    report.close();

    std::cout << "\nResumen guardado en " << filename.str() << "\n";
}

static void print_process(net_event* e, ProcStats &st,std::string key) {
    init_csv();

    long long delta_r = 0, delta_s = 0;
    double r_rate = 0.0, s_rate = 0.0;

    auto it = last_sample.find(e->pid);
    if (it != last_sample.end()) {
        auto prev = it->second;

        unsigned long long delta_ts = st.last_ts - prev.ts;
        if (delta_ts > 0) {
            delta_r = (long long)st.r_bytes - (long long)prev.r_bytes;
            delta_s = (long long)st.s_bytes - (long long)prev.s_bytes;

            double delta_sec = delta_ts / 1e9;

            r_rate = (double)delta_r / delta_sec;
            s_rate = (double)delta_s / delta_sec;
        }
    }
    // actualizar muestra actual
    last_sample[e->pid] = {st.last_ts, st.r_bytes, st.s_bytes};

    /*printf("[%llu] pid=%d Recv=%llu Sent=%llu Rate IN=%.2f B/s OUT=%.2f B/s\n",
           st.last_ts, e->pid, st.r_bytes, st.s_bytes, r_rate, s_rate);*/
    
    

    std::string iface=getActiveInterfaceName();
    // imprimir antes de actualizar snapshots
    printf("[%llu] COMM:%-20s Recv=%llu Sent=%llu Rate: IN=%.2fb/ns OUT=%.2fb/ns (%s) Proto=%s IFACE=%s \n",
           e->ts,
           key.c_str(),
           st.r_bytes,
           st.s_bytes,
           r_rate,
           s_rate,
           e->direction ? "OUT" : "IN",
           e->protocol == IPPROTO_TCP ? "TCP" : "UDP",
           iface.c_str()
    );

    //printf("direction=%u protocol=%u\n", e->direction, e->protocol);
    // Guardar en CSV
        if (csv_file.is_open()) {
                csv_file << std::fixed; // evita notación científica

                csv_file << e->ts << ","                  // timestamp (entero)
                        << e->pid << ","                // pid (entero)
                        << e->comm << ","               // nombre del proceso
                        << st.r_bytes << ","            // bytes recibidos (entero)
                        << st.s_bytes << ",";           // bytes enviados (entero)

                // r_rate y s_rate con 2 decimales
                csv_file << std::setprecision(2)
                        << r_rate << "," << s_rate << ",";

                // el resto sin decimales
                csv_file << std::setprecision(0)
                        << (e->protocol == IPPROTO_TCP ? "TCP" : "UDP") << ","
                        << iface.c_str() << ","
                        << inet_ntoa(*(struct in_addr*)&e->saddr) << "," << e->sport << ","
                        << inet_ntoa(*(struct in_addr*)&e->daddr) << "," << e->dport << ","
                        << st.total_r_bytes << ","
                        << st.total_s_bytes 
                        << "\n";
                    }


    
}

void stats_loop() {
    using clock = std::chrono::steady_clock;
    auto start = clock::now();
    auto next = start;

    while (true) {
        next += std::chrono::seconds(1);
        std::this_thread::sleep_until(next);

        unsigned long long ts = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    next.time_since_epoch()).count();

        print_bandwidth(ts);
    }
}



static void process_event( void *data) {
    struct net_event *e = (struct net_event *) data;

    char keybuf[64];
    snprintf(keybuf, sizeof(keybuf), "%s:%d", e->comm, e->pid);
    std::string key(keybuf);

    if (proc_table.find(key) == proc_table.end()) {
        proc_table[key] = {0, 0, 0, 0, 0}; // inicializa en cero
    }

    auto &st = proc_table[key];
    unsigned long long delta = 0;

    if (e->direction != 0) { // OUT
        if (st.last_s_bytes > 0 && e->bytes >= st.last_s_bytes) {
            delta = e->bytes - st.last_s_bytes;
            st.total_s_bytes += delta;
        } else {
            delta = 0; // evitar underflow
        }
        st.s_bytes = delta;
        st.last_s_bytes = e->bytes;
    } else { // IN
        if (st.last_r_bytes > 0 && e->bytes >= st.last_r_bytes) {
            delta = e->bytes - st.last_r_bytes;
            st.total_r_bytes += delta;
        } else {
            delta = 0;
        }
        st.r_bytes = delta;
        st.last_r_bytes = e->bytes;
    }

    st.last_ts = e->ts;

    if (mode == MODE_EVENTS) {
        print_process(e,st,key);
    } else {
        Stats &bw = process_BW[e->pid];
        bw.comm[sizeof(bw.comm)-1] = '\0';
        strncpy(bw.comm, e->comm, sizeof(bw.comm)-1);

        if (e->direction == 0)
            bw.recv_bytes_window += delta;  // solo sumar delta
        else
            bw.sent_bytes_window += delta;
    }

}





static void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
    std::cerr << "Lost " << lost_cnt << " events on CPU " << cpu << std::endl;
}

int main(int argc, char **argv) {
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

    mode = parse_mode(argc, argv);

    if (mode == MODE_BANDWIDTH) {
        std::thread(stats_loop).detach();
    }

    auto handle_event = [](void *ctx, void *data, size_t size) {
        

            process_event(data);
        
        return 0;
    };
    struct ring_buffer *rb;

    // Asume que ya cargaste tu skeleton
    // skel = monitor_bpf__open_and_load();

    int map_fd = bpf_map__fd(skel->maps.events);

    rb = ring_buffer__new(
        map_fd,
        handle_event,   // callback
        NULL,           // ctx
        NULL            // opts
    );

    if (!rb) {
        fprintf(stderr, "Error creando ring buffer\n");
        return 1;
    }
    

    std::cout << "Tracing... Press Ctrl+C to stop\n";

    while (running) {
        
        int err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0) {
            fprintf(stderr, "Error en ring_buffer__poll: %d\n", err);
            break;
        }
    }
    print_summary();
    if (csv_file.is_open()) {
        csv_file.close();
    }
    ring_buffer__free(rb);
    net_trace_bpf__destroy(skel);
    return 0;
}
