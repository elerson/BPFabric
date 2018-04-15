#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") firewall = {
        .type = BPF_MAP_TYPE_BITMAP,
        .key_size = 2,
        .value_size = 1024,
        .max_entries = 1,
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

uint32_t hash(uint8_t* mac);
uint64_t prog(struct packet *pkt)
{
    // Check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	uint32_t *ret;
	bpf_map_lookup_elem(&firewall, &(ipv4->ip_src), &ret);
	if(*ret == 1)
	    return DROP;

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
