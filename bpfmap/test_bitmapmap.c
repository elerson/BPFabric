#include <stdlib.h>
#include <stdio.h>
#include "bitmapmap.h"

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_BITMAP,
        .key_size = 2,
        .value_size = 1004,
        .max_entries = 1000,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *bitmap_map;
    bitmap_map = bitmap_map_alloc(&attr);


    if (bitmap_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint32_t key1 = 3142392961;
    uint32_t *stats;
    bitmap_map_update_elem(bitmap_map, &key1, NULL, 0);
    stats = bitmap_map_lookup_elem(bitmap_map, &key1);
    printf("%d\n", *stats);
    
    return 0;
    for(int i = 1; i < 200; i+=4){
       key1 = i;
       bitmap_map_update_elem(bitmap_map, &key1, NULL, BPF_ANY);
    }
     //bitmap_map_update_elem(bitmap_map, &key1, NULL, 2);
    for(int i = 1; i < 200; i++){
       key1 = i;
       stats = bitmap_map_lookup_elem(bitmap_map, &key1);
       printf("%d\n", *stats);
    }
     
    key1 =41;
    stats = bitmap_map_lookup_elem(bitmap_map, &key1);
    printf("%d\n", *stats);
    
    bitmap_map_update_elem(bitmap_map, &key1, NULL, 2);
    stats = bitmap_map_lookup_elem(bitmap_map, &key1);
    printf("%d\n", *stats);

    //uint32_t key2 = 1;
    //stats = array_map_lookup_elem(array_map, &key2);
    //printf("%lu\n", stats->packets);*/

    return EXIT_SUCCESS;
}
