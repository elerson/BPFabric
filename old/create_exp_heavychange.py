#!/usr/bin/env python

exp_str = '''
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <stdio.h>
#include "ebpf_switch.h"
#define BPF_MAP_TYPE_MINCOUNT 6
#define BPF_MAP_TYPE_KARY 8

#define NUMCOLS_ ___COLS___
#define NUMROWS_ ___ROWS___
#define PHI_ ___PHI___


struct bpf_map_def SEC("maps") stage0 = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = NUMCOLS_,          // table colums
        .num_rows = NUMROWS_,           // table rows
};

struct bpf_map_def SEC("maps") stage1 = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = NUMCOLS_,          // table colums
        .num_rows = NUMROWS_,           // table rows
};

struct bpf_map_def SEC("maps") stage2 = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,            // hash for each row
        .num_cols = NUMCOLS_,          // table colums
        .num_rows = NUMROWS_,           // table rows
};

struct bpf_map_def SEC("maps") change = {
        .type = BPF_MAP_TYPE_KARY,
        .num_hashes = 1,                // hash for each row
        .num_cols = NUMCOLS_,           // table colums
        .num_rows = NUMROWS_,           // table rows
};


struct arrival_stats {
    uint32_t ip;
    int32_t change;
    uint32_t lasttime;
    uint32_t stage;
    uint32_t cols;
    uint32_t rows;
    uint32_t phi;
    uint32_t c;
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

	uint32_t length = (uint32_t) ((uint16_t) (ipv4->ip_len << 8) | ((ipv4->ip_len >> 8) & 0xFF));//pkt->metadata.length;

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
	int64_t *result;
	bpf_map_lookup_elem(&change, &(ipv4->ip_src), &result);
	
	stats->change = (int32_t) *result;
	if((stats->change > PHI_ || stats->change < -PHI_) && stats->c > 0)
	{	
		stats->cols = NUMCOLS_;
                stats->rows = NUMROWS_;
                stats->phi  = PHI_;	
		stats->ip = *((uint32_t*) &(ipv4->ip_src));
		bpf_notify(0, stats, sizeof(struct arrival_stats));
	}

	if (pkt->metadata.sec - stats->lasttime > 1){
		char str[25];
		str[0] = stats->stage + 48;
		bpf_debug(str);
		//bpf_map_update_elem(&stage0, &(ipv4->ip_src), &length, stats->lasttime);
		stats->lasttime = pkt->metadata.sec;
		switch (stats->stage){
		    case 0:
			bpf_map_update_elem(&stage1, 0, 0, 2);
			//next - change from 0 and 2
			bpf_map_diff_elem(&change, &stage0, &stage2, 0);
			bpf_debug("change 0");
			break;
		    case 1:
			bpf_map_update_elem(&stage2, 0, 0, 2);
			//next - change from 1 and 0
			bpf_map_diff_elem(&change, &stage1, &stage0, 0);
			bpf_debug("change 1");
			break;
		    case 2:
			bpf_map_update_elem(&stage0, 0, 0, 2);
			//next - change from 2 and 1
			bpf_map_diff_elem(&change, &stage2, &stage1, 0);
			bpf_debug("change 2");
			break;
		}
		stats->stage++;
		if(stats->stage >= 3){
		    stats->stage = 0;
                    stats->c++;
		}
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
    with open("examples/tp_heavychange_3.c", 'w') as f:
      f.write(exp_str.replace('___COLS___', str(cols)).replace('___ROWS___', str(hashes)).replace('___PHI___', str(phi)))


if __name__ == "__main__":
  cols = int(sys.argv[1])
  rows     = float(sys.argv[2])
  phi     = float(sys.argv[3])
  exp = Create()
  exp.create(cols, rows, phi)

