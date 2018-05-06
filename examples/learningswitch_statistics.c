#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6

struct bpf_map_def SEC("maps") stats = {
        .type = BPF_MAP_TYPE_MINCOUNT,
        .num_hashes = 2,            // hash for each row
        .num_cols = 100,          // table colums
        .num_rows = 1,           // table rows
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct arrival_stats {
    uint32_t ip;
    uint32_t num_packets;
};

struct bpf_map_def SEC("maps") flowarrival = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};


uint32_t hash(uint8_t* mac);
uint64_t prog(struct packet *pkt)
{
    // Check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	bpf_map_update_elem(&stats, &(ipv4->ip_src), 0, 0);

	//if (pkt->metadata.sec - astats->lasttime > 5) {
	struct arrival_stats *astats;
        unsigned int key = 0;
        bpf_map_lookup_elem(&flowarrival, &key, &astats);

	unsigned int *result;
	bpf_map_lookup_elem(&stats, &(ipv4->ip_src), &result);

	/*if(*result%100000 == 0){
	   astats->num_packets = *result;
	   astats->ip = *((uint32_t*) &(ipv4->ip_src));
	   bpf_notify(0, astats, sizeof(struct arrival_stats));
        }*/

    }

    uint32_t *out_port;

    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood if the destination is broadcast or multicast
    if (pkt->eth.h_dest[0] & 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
uint32_t hash(uint8_t* mac){
    int i;
    uint32_t value = 0;
    for (i = 0; i < 6; i++)
        value += mac[i];
    return value;
}

char _license[] SEC("license") = "GPL";
