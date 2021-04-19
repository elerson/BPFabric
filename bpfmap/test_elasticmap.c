#include <stdlib.h>
#include <stdio.h>
#include "elasticmap.h"

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_MINCOUNT,
        .key_size = 1000, //heavy part size
        .value_size = 10000, //mincount size // cols
        .max_entries = 10, // num lines min count
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *mincount_map, *src2_map;
    mincount_map = elasticmap_map_alloc(&attr);
    src2_map = elasticmap_map_alloc(&attr);


    if (mincount_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint32_t key1 = 41;
    uint32_t *stats;

    stats = elasticmap_map_lookup_elem(mincount_map, &key1);
    printf("%d\n", *stats);

    elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    key1 = 42;
    elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
    
    elasticmap_map_update_elem(src2_map, &key1, NULL, BPF_ANY);
    elasticmap_map_update_elem(src2_map, &key1, NULL, BPF_ANY);
    elasticmap_map_update_elem(src2_map, &key1, NULL, BPF_ANY);
    elasticmap_map_update_elem(src2_map, &key1, NULL, BPF_ANY);
  
    key1 =41;
    stats = elasticmap_map_lookup_elem(mincount_map, &key1);
    printf("%d\n", *stats);
    
    int num_return_keys;
    uint32_t *keys = elasticmap_map_heavy_key_elem(mincount_map, &num_return_keys, 0);
    for(int j = 0; j < num_return_keys; ++j){
       printf("found heavy key %d\n",keys[j]);
    }
    
    keys = elasticmap_map_heavy_change_elem(mincount_map, src2_map, &num_return_keys, 1);
    for(int j = 0; j < num_return_keys; ++j){
       printf("found heavy change %d\n",keys[j]);
    }
    
    


    //return 0;
    int i;
    for (i = 0; i < 10; i++){
      key1 = i;
      elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }
    
    for (i = 75; i < 100; i++){
      key1 = i;
      elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }
    //elasticmap_map_update_elem(mincount_map, &key1, NULL, BPF_CLEAN);
    for (i = 0; i < 100; i++){
      key1 = i;
      stats = elasticmap_map_lookup_elem(mincount_map, &key1);
      printf("(%d) %d\n",i , *stats);
    }

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
