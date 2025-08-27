#ifndef __NET_EVENT_H
#define __NET_EVENT_H

#include <stdint.h>  // estándar C, funciona en C y C++

struct net_event {
    uint64_t ts;        // timestamp
    uint32_t pid;       // PID del proceso
    char comm[16];      // nombre del proceso
    uint32_t saddr;     // IP origen (IPv4)
    uint32_t daddr;     // IP destino (IPv4)
    uint16_t sport;     // puerto origen
    uint16_t dport;     // puerto destino
    uint64_t bytes;     // número de bytes transferidos
    uint8_t  direction; // 0 = recv, 1 = send
    uint8_t  protocol;  // 6 = TCP, 17 = UDP
};

#endif /* __NET_EVENT_H */
