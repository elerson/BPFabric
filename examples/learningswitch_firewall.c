#include <linux/if_ether.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6,
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};


uint32_t hash(void* mac_addr, void* param){

    uint8_t* mac = mac_addr;
    uint32_t param_ = *((uint32_t*)param);
    uint32_t key = 0;
    int i;
    for(i = 0; i < 6; i++)
        key += mac[i]*param_;

    //printf("hash (%d)\n", key_%param_);
    return key;

}

uint32_t params[2] = {7,13};

struct bpf_map_def SEC("maps") firewall = {
    .type = BPF_MAP_TYPE_BITMAP,
    .key_size = 64,
    .value_size = 2,
    .max_entries = 1,
    .map_flags = 0,
};


uint64_t prog(struct packet *pkt)
{

    // Learning switch behaviour
    uint32_t *out_port;
    uint32_t *found;

    /*if(bpf_map_lookup_elem(&firewall, pkt->eth.h_dest, &found) == -1){
        bpf_map_update_elem(&firewall, pkt->eth.h_dest,  0,  BPF_ANY);
        bpf_notify(0, found, sizeof(uint32_t));
    }*/

    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood of the destination is broadcast or multicast
    if ((pkt->eth.h_dest[0] & 1) == 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
char _license[] SEC("license") = "GPL";
