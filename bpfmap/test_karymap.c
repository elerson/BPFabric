#include <stdlib.h>
#include <stdio.h>
#include "karymap.h"

#define BPF_MAP_TYPE_KARY 8

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_KARY,
        .key_size = 4,
        .value_size = 10,
        .max_entries = 2,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *kary_map_dst, *kary_map_src1, *kary_map_src2;
    kary_map_dst  = kary_map_alloc(&attr);
    kary_map_src1 = kary_map_alloc(&attr);
    kary_map_src2 = kary_map_alloc(&attr);


    if (kary_map_dst == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    if (kary_map_src1 == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }


    if (kary_map_src2 == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }


    uint32_t key1;
    uint32_t *stats;
    uint32_t value = 1;
    int i;
    for (i = 0; i < 10; i++){
      key1 = i;
      value = i*i;
      kary_map_update_elem(kary_map_src1, &key1, &value, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }
    
    for (i = 0; i < 10; i++){
      key1 = i;
      value = i;
      kary_map_update_elem(kary_map_src2, &key1, &value, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }

    kary_map_diff_elem(kary_map_dst, kary_map_src2, kary_map_src1, 0);
    for (i = 0; i < 10; i++){
      key1 = i;
      stats = kary_map_lookup_elem(kary_map_dst, &key1);
      printf("(%d) %d\n",i , *stats);
    }

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
