#ifndef __EBPF_SWITCH_H
#define __EBPF_SWITCH_H

#include "ebpf_consts.h"
#include "ebpf_functions.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
    unsigned int type;
    union{
       unsigned int key_size;
       unsigned int num_hashes;
       unsigned int num_heavy;
       unsigned int phi;
    };
    union{
        unsigned int value_size;
        unsigned int num_bits;
        unsigned int num_cols;
    };
    union{
        unsigned int max_entries;
        unsigned int num_rows;
    };   
    
    unsigned int map_flags;
};

inline uint64_t MULTICAST_PORT(uint32_t port1, uint32_t port2){
   if(port1 == port2){
      return port1;
   }

   if(port2 == 0){
      uint64_t port = port1;
      port <<= 32;
      port |= port2;
      return port;
   }
   
   uint64_t port = port2;
   port <<= 32;
   port |= port1;
   return port;
}


inline uint64_t getMac(const unsigned char* mac){
   uint64_t mac_num = 0;
   for(int i = 0; i < ETH_ALEN ; i++){
       mac_num <<= 8;
       mac_num = mac_num | mac[i];
   }
   return mac_num;
}


#endif
