#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_FOO 9
#define NUM_WORKERS ___WORKERS___
#define SINK_PORT ___WORKERS___

uint64_t prog(struct packet *pkt)
{
    uint32_t port = DROP;  
    if (pkt->eth.h_proto == 0x0008){
        uint32_t flow_id = pkt->ip.saddr;
        port = flow_id%NUM_WORKERS;
        
    }
    //bpf_debug2(pkt->ip.saddr, port);
   
    //return MULTICAST_PORT(SINK_PORT, port);
    return MULTICAST_PORT(DROP, port);
}
char _license[] SEC("license") = "GPL";
