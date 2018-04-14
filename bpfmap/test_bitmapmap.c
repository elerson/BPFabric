#include <stdlib.h>
#include <stdio.h>
#include "bitmapmap.h"

struct ewma_stats {
    uint64_t volume;
    uint64_t packets;
    uint64_t prediction;
    uint32_t lasttime;
    uint32_t count;
};

uint32_t hash(void* key, void* param){

    uint32_t key_ = *((uint32_t*)key);
    uint32_t param_ = *((uint32_t*)param);
    printf("hash (%d)\n", key_%param_);
    return key_%param_;

}

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_BITMAP,
        .key_size = 64,
        .value_size = 2,
        .max_entries = 1,
        .map_flags = 0,
        .function_ptr = hash,
        .function_params = params,
        .param_size = 2,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *bitmap_map;
    bitmap_map = bitmap_map_alloc(&attr);

    

    if (bitmap_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint32_t key1 = 41;
    uint32_t *stats;

    stats = bitmap_map_lookup_elem(bitmap_map, &key1);
    printf("%d\n", *stats);

    bitmap_map_update_elem(bitmap_map, &key1, NULL, BPF_ANY);
  
    key1 =41;
    stats = bitmap_map_lookup_elem(bitmap_map, &key1);
    printf("%d\n", *stats);

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
