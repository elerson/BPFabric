#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"

#define DISTSIZE 256.0
#define BINSIZE 7

struct bpf_map_def SEC("maps") flow_dist = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t), // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};


struct arrival_stats {
    uint32_t bin;
    uint32_t bin_value;
};

struct bpf_map_def SEC("maps") temp = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t), // MAC address is the key
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};

uint64_t prog(struct packet *pkt)
{

    struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth));
    if (ipv4->ip_v == 4){
        
        struct arrival_stats *tp;
	uint32_t key = 0;
	bpf_map_lookup_elem(&temp, &key, &tp);

	uint32_t length = (uint32_t) ((uint16_t) (ipv4->ip_len << 8) | ((ipv4->ip_len >> 8) & 0xFF));//pkt->metadata.length;
	tp->bin = length/BINSIZE;
	
	uint32_t *num_ips;
	bpf_map_lookup_elem(&flow_dist, &tp->bin, &num_ips);
        tp->bin_value = *num_ips + 1;
	bpf_map_update_elem(&flow_dist, &tp->bin, &tp->bin_value, 0);
        
	
    }
    return FLOOD;

}
char _license[] SEC("license") = "GPL";
