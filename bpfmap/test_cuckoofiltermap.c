#include <stdlib.h>
#include <stdio.h>
#include "cuckoofiltermap.h"


int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_BITMAP,
        .key_size = 1,
        .value_size = 20, //lines
        .max_entries = 20, //colums
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *bitmap_map;
    bitmap_map = cuckoofilter_map_alloc(&attr);


    if (bitmap_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint32_t key1 = 41;
    int32_t  value1 = 100;
    int32_t *stats;

    stats = cuckoofilter_map_lookup_elem(bitmap_map, &key1);
    printf("%d\n", *stats);
    
    
    for(int i = 1; i < 100; ++i){
      key1 = i;
      value1 = i;
      cuckoofilter_map_update_elem(bitmap_map, &key1, &value1, BPF_ANY);
    }
    
    for(int i = 1; i < 100; ++i){
      key1 = i;
      stats = cuckoofilter_map_lookup_elem(bitmap_map, &key1);
      printf(" %d %d\n", i, *stats);
    }

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
