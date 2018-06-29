#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6
#define BPF_MAP_TYPE_KARY 8

struct bpf_map_def SEC("maps") stage0 = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = 100,          // table colums
        .num_rows = 20,           // table rows
};

struct bpf_map_def SEC("maps") stage1 = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = 100,          // table colums
        .num_rows = 20,           // table rows
};

struct bpf_map_def SEC("maps") stage2 = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = 100,          // table colums
        .num_rows = 20,           // table rows
};

struct bpf_map_def SEC("maps") change = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = 100,          // table colums
        .num_rows = 20,           // table rows
};



struct arrival_stats {
    uint32_t ip;
    uint32_t change;
    uint32_t lasttime;
    uint32_t stage;
};

struct bpf_map_def SEC("maps") count_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};


uint32_t stage = 0;

uint64_t prog(struct packet *pkt)
{
	
    struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth));
    if (ipv4->ip_v == 4){

	uint32_t length = ipv4->ip_len;//pkt->metadata.length;

	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&count_stats, &key, &stats);
        
	switch (stats->stage){
	    case 0:
		bpf_map_update_elem(&stage0, &(ipv4->ip_src), &length, 0);
		break;
	    case 1:
		bpf_map_update_elem(&stage1, &(ipv4->ip_src), &length, 0);
		break;
	    case 2:
		bpf_map_update_elem(&stage2, &(ipv4->ip_src), &length, 0);
		break;
	}
	//Detect change
	uint32_t *result;
	bpf_map_lookup_elem(&change, &(ipv4->ip_src), &result);

	if(*result > 100000000){
		stats->change = *result;
		stats->ip = *((uint32_t*) &(ipv4->ip_src));
		bpf_notify(0, stats, sizeof(struct arrival_stats));
	}

	if (pkt->metadata.sec - stats->lasttime > 1){
		//bpf_map_update_elem(&stage0, &(ipv4->ip_src), &length, stats->lasttime);
		stats->lasttime = pkt->metadata.sec;
		switch (stats->stage){
		    case 0:
			bpf_map_update_elem(&stage1, 0, 0, 2);
			//next - change from 0 and 2
			bpf_map_diff_elem(&change, &stage0, &stage2, 0);
			break;
		    case 1:
			bpf_map_update_elem(&stage2, 0, 0, 2);
			//next - change from 1 and 0
			bpf_map_diff_elem(&change, &stage1, &stage0, 0);
			break;
		    case 2:
			bpf_map_update_elem(&stage0, 0, 0, 2);
			//next - change from 2 and 1
			bpf_map_diff_elem(&change, &stage2, &stage1, 0);
			break;
		}
		stats->stage++;
		if(stats->stage >= 3)
		    stats->stage = 0;
        }

    }

    return FLOOD;
}
char _license[] SEC("license") = "GPL";
