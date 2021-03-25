#!/usr/bin/env python

exp_str = '''
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6

#define COLS_ ___COLS___
#define HASHES_ ___HASHES___
#define PHI_ ___PHI___

struct bpf_map_def SEC("maps") sketch_count = {
        .type = BPF_MAP_TYPE_MINCOUNT,
        .num_hashes = HASHES_,            // hash for each row
        .num_cols = COLS_,          // table colums
        .num_rows = 1,           // table rows
};


struct arrival_stats {
    uint32_t ip;
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
	uint32_t length = (uint32_t) ((uint16_t) (ipv4->ip_len << 8) | ((ipv4->ip_len >> 8) & 0xFF));//pkt->metadata.length;
	bpf_map_update_elem(&sketch_count, &(ipv4->ip_src), &length, 0);

	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&count_stats, &key, &stats);

	if (pkt->metadata.sec - stats->lasttime < 1) {	 
		unsigned int *result_sketch;
		bpf_map_lookup_elem(&sketch_count, &(ipv4->ip_src), &result_sketch);

		if(*result_sketch > PHI_){
		   stats->sketch_count = *result_sketch;
		   stats->hashes = HASHES_;
		   stats->cols = COLS_;
		   stats->phi  = PHI_;
		   stats->ip = *((uint32_t*) &(ipv4->ip_src));
		   bpf_notify(0, stats, sizeof(struct arrival_stats));
		}
        }else{
		stats->lasttime = pkt->metadata.sec;
		//clean min count
		bpf_map_update_elem(&sketch_count, 0, 0, 2);
		
	}

    }

    return FLOOD;
}
char _license[] SEC("license") = "GPL";
'''


import sys
import os
import math

class Create():
  def create(self, cols, hashes, phi):
    with open("examples/tp_heavyhitter_3.c", 'w') as f:
      f.write(exp_str.replace('___COLS___', str(cols)).replace('___HASHES___', str(hashes)).replace('___PHI___', str(phi)))


if __name__ == "__main__":
  cols = int(sys.argv[1])
  hashes     = float(sys.argv[2])
  phi     = float(sys.argv[3])
  exp = Create()
  exp.create(cols, hashes, phi)

