#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpf_switch.h"


#define COLS_ ___COLS___
#define ROWS_ ___ROWS___
#define HASHES_ ___HASHES___
#define PHI_ ___PHI___
#define TIME __TIME__

//
// #define BPF_MAP_TYPE_BITMAP 5
//#define BPF_MAP_TYPE_MINCOUNT 6
//#define BPF_MAP_TYPE_MVSKETCH 9
//#define BPF_MAP_TYPE_ELASTIC 10
//#define BPF_MAP_TYPE_CUCKOO 11
//#define BPF_MAP_TYPE_LDSKETCH 12
//
//

#define MVSKETCH

#ifdef MVSKETCH
struct bpf_map_def SEC("maps") stage0 = {
        .type = BPF_MAP_TYPE_MVSKETCH,
        .num_hashes = HASHES_,        // HASHES_
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,             // table rows
};

struct bpf_map_def SEC("maps") stage1 = {
        .type = BPF_MAP_TYPE_MVSKETCH,
        .num_hashes = HASHES_,        // HASHES_
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,             // table rows
};

#endif

/*
#ifdef LDSKETCH
struct bpf_map_def SEC("maps") stage0 = {
        .type = BPF_MAP_TYPE_LDSKETCH,
        .phi = PHI_/4,        // HASHES_
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,              // table rows
};

struct bpf_map_def SEC("maps") stage1 = {
        .type = BPF_MAP_TYPE_LDSKETCH,
        .phi = PHI_/4,        // HASHES_
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,              // table rows
};
#endif
*/



struct arrival_stats {
    uint32_t ip;
    uint32_t hashes;
    uint32_t cols;
    uint32_t phi;
    uint32_t rows;
    uint32_t lasttime;
    uint32_t stage;
    uint64_t dst[3];
};



struct bpf_map_def SEC("maps") count_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
};


uint64_t prog(struct packet *pkt)
{
     
    
    if (pkt->eth.h_proto == 0x0008){	
    
        struct arrival_stats *stats;
        unsigned int key = 0;
        bpf_map_lookup_elem(&count_stats, &key, &stats);
	
	uint32_t length = (uint32_t) ((uint16_t) (pkt->ip.tot_len << 8) | ((pkt->ip.tot_len >> 8) & 0xFF));//pkt->metadata.length;  
        switch (stats->stage){
            case 0:
                bpf_map_update_elem(&stage0, &(pkt->ip.saddr), &length, 0);
                break;
            case 1:
                bpf_map_update_elem(&stage1, &(pkt->ip.saddr), &length, 0);
                break;
	}
        
        uint32_t id = (uint32_t) getMac(pkt->eth.h_source);
        stats->dst[id] = getMac(pkt->eth.h_dest);
	//bpf_map_update_elem(&sketch_count, &(pkt->ip.saddr), &length, 0);
       
	if (pkt->metadata.sec - stats->lasttime >= TIME) {
	        
		stats->lasttime = pkt->metadata.sec;		
	
	        stats->cols = COLS_;
		stats->rows = ROWS_;
		stats->phi = PHI_;
		stats->hashes = HASHES_;
		
		bpf_notify(1, stats, sizeof(struct arrival_stats));
		
               uint32_t nums_elements;
               uint32_t *keys;
               switch (stats->stage){
                 case 0:
                    keys = bpf_map_heavy_change_elem(&stage1, &stage0, &nums_elements, PHI_);                    
                    break;
                 case 1:
                    keys = bpf_map_heavy_change_elem(&stage0, &stage1, &nums_elements, PHI_);                    
                    break;
	         }
	
		
		bpf_notify(2, keys, sizeof(uint32_t)*nums_elements);
		
		
		if(stats->stage == 0){
		    bpf_map_update_elem(&stage1, 0, 0, 2);
		    stats->stage = 1;
		}else{
		    bpf_map_update_elem(&stage0, 0, 0, 2);
		    stats->stage = 0;
		}
		
		//clean min count
		
	}

    }

    return MULTICAST_PORT(DROP, DROP);
}
char _license[] SEC("license") = "GPL";
