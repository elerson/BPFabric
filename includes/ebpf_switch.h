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

#endif
