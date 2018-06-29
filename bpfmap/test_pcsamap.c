#include <stdlib.h>
#include <stdio.h>
#include "pcsamap.h"

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_PCSA,
        .key_size = sizeof(uint32_t),
        .value_size = 1,
        .max_entries = 128,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *pcsa_map;
    pcsa_map = pcsa_map_alloc(&attr);


    if (pcsa_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint64_t i;
    for(i = 0; i < 10000000; i++){
        int key1 = i;
        pcsa_map_update_elem(pcsa_map, &key1, NULL, BPF_ANY);
        uint32_t *ret = pcsa_map_lookup_elem(pcsa_map, NULL);

        printf("%f %d %d\n", ((float)abs(*ret - i))/i, i, *ret);

    }


    

    

    /*
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
