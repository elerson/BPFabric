#include <stdlib.h>
#include <stdio.h>
#include "foo_map.h"

#define BPF_MAP_TYPE_KARY 8

int main() {

    uint32_t params[2] = {7,50};

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_FOO,
        .key_size = 4,
        .value_size = 10,
        .max_entries = 2,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *foo_map;
    foo_map  = foo_map_alloc(&attr);

    if (foo_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }


    int i;
    for (i = 0; i < 30; i++){
      foo_map_update_elem(foo_map,NULL, NULL, BPF_ANY);
      //printf("(%d) %d\n",i , *stats);
    }

    int *stats;
    stats = foo_map_lookup_elem(foo_map, NULL);

    printf("%d \n", *stats);



    return EXIT_SUCCESS;
}
