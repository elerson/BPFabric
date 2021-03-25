#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6
#define BPF_MAP_TYPE_PCSA 7

struct bpf_map_def SEC("maps") counter = {
        .type = BPF_MAP_TYPE_PCSA,
        .key_size = sizeof(uint32_t),
        .max_entries = 9048,
};


struct arrival_stats {
    uint32_t num_ips;
    uint32_t lasttime;
};

struct bpf_map_def SEC("maps") temp = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};


uint64_t prog(struct packet *pkt)
{

    struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth));
    if (ipv4->ip_v == 4){

	uint32_t length = (uint32_t) ((uint16_t) (ipv4->ip_len << 8) | ((ipv4->ip_len >> 8) & 0xFF));//pkt->metadata.length;
	bpf_map_update_elem(&counter, &(ipv4->ip_src), 0, 0);

	
	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&temp, &key, &stats);

	if (pkt->metadata.sec - stats->lasttime > 1) {	 
		stats->lasttime = pkt->metadata.sec;
		uint32_t *num_ips;
		bpf_map_lookup_elem(&counter, 0, &num_ips);
		stats->num_ips = *num_ips;
		bpf_notify(0, stats, sizeof(struct arrival_stats));
		bpf_map_update_elem(&counter, 0, 0, 2);
		
	}

    }

    return FLOOD;
}
char _license[] SEC("license") = "GPL";
