#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6

#define COLS_ 500
#define HASHES_ 2
#define PHI_ 100000000

struct bpf_map_def SEC("maps") sketch_count = {
        .type = BPF_MAP_TYPE_MINCOUNT,
        .num_hashes = HASHES_,            // hash for each row
        .num_cols = COLS_,          // table colums
        .num_rows = 1,           // table rows
};


struct bpf_map_def SEC("maps") sketch_count2 = {
        .type = BPF_MAP_TYPE_MINCOUNT,
        .num_hashes = 3,            // hash for each row
        .num_cols = 10000000,          // table colums
        .num_rows = 1,           // table rows
};


struct bpf_map_def SEC("maps") real_count = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t), // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};


struct arrival_stats {
    uint32_t ip;
    uint32_t real_count;
    uint32_t sketch_count;
    uint32_t hashes;
    uint32_t cols;
    uint32_t phi;
    uint32_t lasttime;
};

struct bpf_map_def SEC("maps") count_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};


uint64_t prog(struct packet *pkt)
{

    struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth));
    if (ipv4->ip_v == 4){	
	
	// Update the skecth count
	uint32_t length = ipv4->ip_len;//pkt->metadata.length;
	bpf_map_update_elem(&sketch_count, &(ipv4->ip_src), &length, 0);
	bpf_map_update_elem(&sketch_count2, &(ipv4->ip_src), &length, 0);

	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&count_stats, &key, &stats);

	if (pkt->metadata.sec - stats->lasttime < 1) {	 
		unsigned int *result_sketch, *result_real;
		bpf_map_lookup_elem(&sketch_count, &(ipv4->ip_src), &result_sketch);

		bpf_map_lookup_elem(&sketch_count2, &(ipv4->ip_src), &result_real);


		if(*result_real > PHI_){
		   stats->sketch_count = *result_sketch;
		   stats->real_count = *result_real;
		   stats->hashes = HASHES_;
		   stats->cols = COLS_;
		   stats->phi  = PHI_;
		   stats->ip = *((uint32_t*) &(ipv4->ip_src));
		   bpf_notify(0, stats, sizeof(struct arrival_stats));
		}
        }else{
		stats->lasttime = pkt->metadata.sec;
		//bpf_map_update_elem(&stats, &pkt->eth.h_proto, &key, pkt->eth.h_proto);
		//clean min count
		bpf_map_update_elem(&sketch_count, 0, 0, 2);
		bpf_map_update_elem(&sketch_count2, 0, 0, 2);
		
	}

    }

    return FLOOD;
}
char _license[] SEC("license") = "GPL";
