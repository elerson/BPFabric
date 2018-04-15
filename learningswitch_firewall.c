#include <linux/if_ether.h>
#include "ebpf_switch.h"



struct bpf_map_def SEC("maps") traffichist = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 24,
};




uint64_t prog(struct packet *pkt)
{

    // Learning switch behaviour
    uint32_t *out_port;
    //uint32_t *found;

    /*if(bpf_map_lookup_elem(&t, pkt->eth.h_dest, &out_port) == -1){
        bpf_map_update_elem(&t,  pkt->eth.h_source, &pkt->metadata.in_port, 0);
        //bpf_notify(0, found, sizeof(uint32_t));
    }*/
	
    /*if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&firewall, pkt->eth.h_source, &pkt->metadata.in_port, 0);
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
