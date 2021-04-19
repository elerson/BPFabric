#include <stdlib.h>
#include <stdio.h>
#include "mvsketchmap.h"
#include "map/map.h"
#define BPF_MAP_TYPE_KARY 8

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_KARY,
        .key_size = 3,
        .value_size = 10000,
        .max_entries = 10,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *kary_map_dst, *kary_map_src1, *kary_map_src2, *kary_map_src3;
    kary_map_dst  = mvsketch_map_alloc(&attr);
    kary_map_src1 = mvsketch_map_alloc(&attr);
    kary_map_src2 = mvsketch_map_alloc(&attr);


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
    for (i = 1; i < 10; i++){
      value = 3991793133;
      mvsketch_map_update_elem(kary_map_src1, &key1, &value, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }

    for (i = 1; i < 10; i++){
      key1 = 3991793133;
      value = 1;
      mvsketch_map_update_elem(kary_map_src2, &key1, &value, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }

   
    
   
    
    mvsketch_map_diff_elem(kary_map_dst, kary_map_src2, kary_map_src1, 0);
    
 
    for (i = 1; i < 10; i++){
      key1 = 3991793133;
      stats = mvsketch_map_lookup_elem(kary_map_src2, &key1);
      printf("(%d) %d\n",i , *stats);
    }
    int num_return_keys;
    uint32_t *keys;
    /*keys = mvsketch_map_heavy_key_elem(kary_map_src2, &num_return_keys, 40);
    
    for (i = 0; i < num_return_keys; i++){
      printf("heavy key (%d)\n", keys[i]);
    }*/
    
    
    keys = mvsketch_map_heavy_key_elem(kary_map_src2, &num_return_keys, 3);
    
    //keys = mvsketch_map_heavy_key_elem(kary_map_src2, &num_return_keys, 50);
    for (i = 0; i < num_return_keys; i++){
      printf("heavy change key (%d)\n", keys[i]);
    }
    
    
    key1 = 3991793133;
    char new_key[5];
    uint_to_char(key1, new_key);
    printf("KEY %ld %ld \n", key1, char_to_uint(new_key));
    
    return 0;
    

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
