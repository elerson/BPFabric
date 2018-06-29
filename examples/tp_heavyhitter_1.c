#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6

struct bpf_map_def SEC("maps") stats = {
        .type = BPF_MAP_TYPE_MINCOUNT,
        .num_hashes = 3,            // hash for each row
        .num_cols = 100,          // table colums
        .num_rows = 20,           // table rows
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
    uint32_t lasttime;
};

struct bpf_map_def SEC("maps") flowarrival = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};


uint64_t prog(struct packet *pkt)
{
    // Check if the ethernet frame contains an ipv4 payload
    //printf("teste \n");
    //unsigned int key = 0;
    //bpf_map_update_elem(&stats, 0, 0, pkt->eth.h_proto);
    //if (pkt->eth.h_proto == 0x0008) 
    //{
	
    struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth));
    if (ipv4->ip_v == 4){

	

	uint32_t length = ipv4->ip_len;//pkt->metadata.length;
	bpf_map_update_elem(&stats, &(ipv4->ip_src), &length, 0);

	
	struct arrival_stats *astats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&flowarrival, &key, &astats);

	if (pkt->metadata.sec - astats->lasttime < 1) {	 
		unsigned int *result;
		bpf_map_lookup_elem(&stats, &(ipv4->ip_src), &result);
		

		if(*result > 100000000){
		   astats->num_packets = *result;
		   astats->ip = *((uint32_t*) &(ipv4->ip_src));
		   bpf_notify(0, astats, sizeof(struct arrival_stats));
		}
        }else{
		astats->lasttime = pkt->metadata.sec;
		//bpf_map_update_elem(&stats, &pkt->eth.h_proto, &key, pkt->eth.h_proto);
		//clean min count
		bpf_map_update_elem(&stats, 0, 0, 2);
		
	}

    }

    return FLOOD;
}
char _license[] SEC("license") = "GPL";
