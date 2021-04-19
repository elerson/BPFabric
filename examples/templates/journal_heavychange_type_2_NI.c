#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpf_switch.h"
#include <stdlib.h> 

#define COLS_ ___COLS___
#define ROWS_ ___ROWS___
#define HASHES_ ___HASHES___
#define PHI_ ___PHI___

#define TIME __TIME__
#define ___MAP___ BPF_MAP_TYPE_KARY


struct bpf_map_def SEC("maps") identification_map = {
        .type = BPF_MAP_TYPE_BITMAP,
        .num_hashes = 2,      // hashes - k
        .num_bits = 10024, // bits in the table
        .num_rows = 100,   // number rows in the table
};



struct bpf_map_def SEC("maps") stage0 = {
        .type = ___MAP___,
        .num_hashes = HASHES_,            // hash for each row
        .num_cols = COLS_,          // table colums
        .num_rows = ROWS_,           // table rows
};

struct bpf_map_def SEC("maps") stage1 = {
        .type = ___MAP___,
        .num_hashes = HASHES_,            // hash for each row
        .num_cols = COLS_,          // table colums
        .num_rows = ROWS_,           // table rows
};

struct bpf_map_def SEC("maps") stage2 = {
        .type = ___MAP___,
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
	
	struct arrival_stats *stats;
	unsigned int key = 0;
	bpf_map_lookup_elem(&count_stats, &key, &stats);
       
       
	int64_t length = (int64_t) ((uint16_t) (pkt->ip.tot_len << 8) | ((pkt->ip.tot_len >> 8) & 0xFF));//pkt->metadata.length;
	switch (stats->stage){
	    case 0:
		bpf_map_update_elem(&stage0, &(pkt->ip.saddr), &length, 0);
		break;
	    case 1:
		bpf_map_update_elem(&stage1, &(pkt->ip.saddr), &length, 0);
		break;
	    case 2:
		bpf_map_update_elem(&stage2, &(pkt->ip.saddr), &length, 0);
		break;
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
		int64_t *result_sketch1;
		int64_t *result_sketch2;
		//bpf_map_lookup_elem(&sketch_count, &(pkt->ip.saddr), &result_sketch);
               switch (stats->stage){
	          case 0:
	 	     bpf_map_lookup_elem(&stage1, &(pkt->ip.saddr), &result_sketch1);
	 	     bpf_map_lookup_elem(&stage2, &(pkt->ip.saddr), &result_sketch2);
		  break;
	          case 1:
		     bpf_map_lookup_elem(&stage0, &(pkt->ip.saddr), &result_sketch1);
		     bpf_map_lookup_elem(&stage2, &(pkt->ip.saddr), &result_sketch2);
		   break;
	          case 2:
		     bpf_map_lookup_elem(&stage0, &(pkt->ip.saddr), &result_sketch1);
		     bpf_map_lookup_elem(&stage1, &(pkt->ip.saddr), &result_sketch2);
		  break;
	        }


                int64_t change = llabs(*result_sketch1 - *result_sketch2);
               // bpf_debug2(pkt->ip.saddr, *result_sketch);
		if(change > PHI_){
		 

		   stats->ip   = pkt->ip.saddr;
		   
		   bpf_notify(0, stats, sizeof(struct arrival_stats));
		   		   
		   bpf_map_update_elem(&identification_map, &(pkt->ip.saddr), 0, 0);
		}
		
		
        }else{
               
		stats->lasttime = pkt->metadata.sec;		
	
	        stats->cols = COLS_;
		stats->rows = ROWS_;
		stats->phi = PHI_;
		stats->hashes = HASHES_;


		bpf_notify(1, stats, sizeof(struct arrival_stats));
		
		if(stats->stage == 0){
		   bpf_map_update_elem(&stage1, 0, 0, 2);
		   stats->stage = 1;
		}else if(stats->stage == 1){
		   bpf_map_update_elem(&stage2, 0, 0, 2);
		   stats->stage = 2;
		}else{
		   bpf_map_update_elem(&stage0, 0, 0, 2);
		   stats->stage = 0;
		}
		//clean min count
		
		bpf_map_update_elem(&identification_map, 0, 0, 2);
	}

    }

    return DROP;
}
char _license[] SEC("license") = "GPL";
