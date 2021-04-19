#include <stdlib.h>
#include <stdio.h>
#include "mincountmap.h"

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_MINCOUNT,
        .key_size = 4,
        .value_size = 10000,
        .max_entries = 2,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *mincount_map;
    mincount_map = mincountmap_map_alloc(&attr);


    if (mincount_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint32_t key1 = 41;
    uint32_t *stats;

    stats = mincountmap_map_lookup_elem(mincount_map, &key1);
    printf("%d\n", *stats);

    mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    key1 = 40;
    mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
  
    key1 =41;
    stats = mincountmap_map_lookup_elem(mincount_map, &key1);
    printf("%d\n", *stats);
   
    int i;
    for (i = 0; i < 100; i++){
      key1 = i;
      mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }
    
    for (i = 75; i < 100; i++){
      key1 = i;
      mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }
    
    //mincountmap_map_update_elem(mincount_map, &key1, NULL, BPF_CLEAN);
    for (i = 0; i < 100; i++){
      key1 = i;
      stats = mincountmap_map_lookup_elem(mincount_map, &key1);
      printf("(%d) %d\n",i , *stats);
    }

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
