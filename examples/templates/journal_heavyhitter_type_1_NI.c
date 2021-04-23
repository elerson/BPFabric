#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpf_switch.h"


#define COLS_ ___COLS___
#define ROWS_ ___ROWS___
#define HASHES_ ___HASHES___
#define PHI_ ___PHI___
#define MAP_DEF_ ___MAP___
#define TIME __TIME__

//BPF_MAP_TYPE_MINCOUNT BPF_MAP_TYPE_KARY

struct bpf_map_def SEC("maps") identification_map = {
        .type = BPF_MAP_TYPE_BITMAP,
        .num_hashes = 2,      // hashes - k
        .num_bits = 10000, // bits in the table
        .num_rows = 10,   // number rows in the table
};

struct bpf_map_def SEC("maps") sketch_count = {
        .type = MAP_DEF_,
        .num_hashes = HASHES_,            // hash for each row
        .num_cols = COLS_,          // table colums
        .num_rows = ROWS_,           // table rows
};


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
     
    //bpf_debug2(pkt->ip.saddr, pkt->eth.h_proto);  
    if (pkt->eth.h_proto == 0x0008){	

	//bpf_debug2(pkt->ip.saddr, 0);  
	// Update the skecth count
	uint32_t length = 1;//(uint32_t) ((uint16_t) (pkt->ip.tot_len << 8) | ((pkt->ip.tot_len >> 8) & 0xFF));//pkt->metadata.length;
	bpf_map_update_elem(&sketch_count, &(pkt->ip.saddr), &length, 0);

	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&count_stats, &key, &stats);
        if(stats->lasttime == 0){
           stats->lasttime = pkt->metadata.sec;
        }
       
        
        uint32_t *found;
	bpf_map_lookup_elem(&identification_map, &(pkt->ip.saddr), &found);
	
        uint32_t id = (uint32_t) getMac(pkt->eth.h_source);
        stats->dst[id] = getMac(pkt->eth.h_dest);
        if(((pkt->metadata.sec - stats->lasttime) < TIME) && (*found == 1)){
           //bpf_debug2(pkt->ip.saddr, *found); 
           return DROP;
        }
           
        //bpf_debug2(pkt->ip.saddr, *found);  

	if (pkt->metadata.sec - stats->lasttime < TIME) {	 
		unsigned int *result_sketch;
		bpf_map_lookup_elem(&sketch_count, &(pkt->ip.saddr), &result_sketch);

               // bpf_debug2(pkt->ip.saddr, *result_sketch);
		if(*result_sketch > PHI_){
		 
		   //stats->sketch_count = *result_sketch;

		   stats->ip   = pkt->ip.saddr;
		   
		   bpf_notify(0, stats, sizeof(struct arrival_stats));
		   //bpf_debug2(pkt->ip.saddr, *found); 	   
		   bpf_map_update_elem(&identification_map, &(pkt->ip.saddr), 0, 0);
		}
        }else{
               bpf_notify(1, stats, sizeof(struct arrival_stats));
               
		stats->lasttime = pkt->metadata.sec;
		
		
	        stats->cols = COLS_;
		stats->rows = ROWS_;
		stats->phi = PHI_;
		stats->hashes = HASHES_;
		
		bpf_notify(1, stats, sizeof(struct arrival_stats));
		
		
		//clean min count
		bpf_map_update_elem(&sketch_count, 0, 0, 2);
		bpf_map_update_elem(&identification_map, 0, 0, 2);
	}

    }

    return DROP;
}
char _license[] SEC("license") = "GPL";
