#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpf_switch.h"


#define COLS_ ___COLS___
#define ROWS_ ___ROWS___
#define HASHES_ ___HASHES___
#define PHI_ ___PHI___
#define ___MAP___
#define NUM_HEAVY ___NUM_HEAVY___
#define TIME __TIME__

// ELASTIC MVSKETCH


//
// #define BPF_MAP_TYPE_BITMAP 5
//#define BPF_MAP_TYPE_MINCOUNT 6
//#define BPF_MAP_TYPE_MVSKETCH 9
//#define BPF_MAP_TYPE_ELASTIC 10
//#define BPF_MAP_TYPE_CUCKOO 11
//#define BPF_MAP_TYPE_LDSKETCH 12
//
//


#ifdef ELASTIC
struct bpf_map_def SEC("maps") sketch_count = {
        .type = BPF_MAP_TYPE_ELASTIC,
        .num_heavy = NUM_HEAVY,      // NUM_HEAVY
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,              // table rows
};
#endif


#ifdef MVSKETCH
struct bpf_map_def SEC("maps") sketch_count = {
        .type = BPF_MAP_TYPE_MVSKETCH,
        .num_heavy = HASHES_,        // HASHES_
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,             // table rows
};
#endif

/*#ifdef LDSKETCH
struct bpf_map_def SEC("maps") sketch_count = {
        .type = BPF_MAP_TYPE_LDSKETCH,
        .phi = PHI_,        // HASHES_
        .num_cols = COLS_,           // table colums
        .num_rows = ROWS_,              // table rows
};
#endif*/



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

	
	//bpf_debug2(pkt->ip.saddr, 12);  
	// Update the skecth count
	uint32_t length = 1;//(uint32_t) ((uint16_t) (pkt->ip.tot_len << 8) | ((pkt->ip.tot_len >> 8) & 0xFF));//pkt->metadata.length;
	bpf_map_update_elem(&sketch_count, &(pkt->ip.saddr), &length, 0);

	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&count_stats, &key, &stats);
        
        uint32_t id = (uint32_t) getMac(pkt->eth.h_source);
        stats->dst[id] = getMac(pkt->eth.h_dest);
	if (pkt->metadata.sec - stats->lasttime >= TIME) {
	        
		stats->lasttime = pkt->metadata.sec;
		
		stats->cols = COLS_;
		stats->rows = ROWS_;
		stats->phi = PHI_;
		stats->hashes = HASHES_;
		
		/*for(int i = 0; i < ETH_ALEN ; i++){
		       stats->src <<= 8;
		       stats->src = stats->src | pkt->eth.h_source[i];
			  
		       stats->dst <<= 8;
		       stats->dst = stats->dst | pkt->eth.h_dest[i];
		}*/
		
		
		bpf_notify(1, stats, sizeof(struct arrival_stats));
		
		//notify heavy keys
		uint32_t nums_elements;
		//bpf_debug2(pkt->ip.saddr, sketch_count.key_size);
		uint32_t *keys = bpf_map_heavy_key_elem(&sketch_count, &nums_elements, PHI_);
		//bpf_debug2(pkt->ip.saddr, nums_elements); 
		if(nums_elements > 0){
		   bpf_notify(2, keys, sizeof(uint32_t)*nums_elements);
		}
		
		//clean min count
		bpf_map_update_elem(&sketch_count, 0, 0, 2);
	}

    }

    return MULTICAST_PORT(DROP, DROP);
}
char _license[] SEC("license") = "GPL";
