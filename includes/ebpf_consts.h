#ifndef __EBPF_SWITCH_CONSTS_H
#define __EBPF_SWITCH_CONSTS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
//#include <netinet/ip.h>
#include <linux/ip.h>
#include <stdint.h>


#define BPF_MAP_TYPE_BITMAP 5
#define BPF_MAP_TYPE_MINCOUNT 6
#define BPF_MAP_TYPE_MVSKETCH 9
#define BPF_MAP_TYPE_KARY 8
#define BPF_MAP_TYPE_ELASTIC 10
#define BPF_MAP_TYPE_CUCKOO 11
#define BPF_MAP_TYPE_LDSKETCH 12

#define MCAST      0xfffffffc
#define FLOOD      0xfffffffd
#define CONTROLLER 0xfffffffe
#define DROP       0xffffffff

struct metadatahdr { // limited to the size available between the TPACKET_V2 header and the tp_mac payload
    uint32_t in_port;
    uint32_t sec;
    uint32_t nsec;
    uint16_t length;
} __attribute__((packed));


struct packet {
    struct metadatahdr metadata;
    struct ethhdr eth;
    struct iphdr ip;
};

#endif
