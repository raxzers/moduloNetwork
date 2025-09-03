#ifndef __NET_EVENT_H
#define __NET_EVENT_H

#include <stdint.h>  // estándar C, funciona en C y C++

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
    char ifname[16];

};
#endif /* __NET_EVENT_H */
