#include <stdlib.h>
#include <stdio.h>
#include "ldsketchmap.h"

#define BPF_MAP_TYPE_KARY 8

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_KARY,
        .key_size = 2,
        .value_size = 10000,
        .max_entries = 100,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *kary_map_src1, *kary_map_src2;

    kary_map_src1 = ldsketch_map_alloc(&attr);
    kary_map_src2 = ldsketch_map_alloc(&attr);

    if (kary_map_src1 == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }


    uint32_t key1;
    uint32_t *stats;
    uint32_t value = 1;
    int i;
    for (i = 1; i < 10; i++){
      key1 = i;
      value = 20;
      ldsketch_map_update_elem(kary_map_src1, &key1, &value, BPF_ANY);
      
      value = 20+i;
      ldsketch_map_update_elem(kary_map_src2, &key1, &value, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }
    int count_h;
    uint32_t *r_keys = ldsketch_map_heavy_key_elem(kary_map_src1, &count_h, 5);
    
    for(i = 0; i < count_h; ++i){
       printf("heavy key %d\n", r_keys[i]);
    }
    


    
    count_h;
    r_keys = ldsketch_map_heavy_change_elem(kary_map_src2, kary_map_src1, &count_h, 5);
    
    for(i = 0; i < count_h; ++i){
       printf("heavy change %d\n", r_keys[i]);
    }
    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
