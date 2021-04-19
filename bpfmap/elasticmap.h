#ifndef __EBPF_ELASTICMAP_H
#define __EBPF_ELASTICMAP_H

#include "bpfmap.h"

struct bpf_map *elasticmap_map_alloc(union bpf_attr *attr);
void elasticmap_map_free(struct bpf_map *map);
void *elasticmap_map_lookup_elem(struct bpf_map *map, void *key);
int elasticmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int elasticmap_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int elasticmap_map_delete_elem(struct bpf_map *map, void *key);
void* elasticmap_map_heavy_key_elem(struct bpf_map *map, int *num_return_keys, int phi);
void* elasticmap_map_heavy_change_elem(struct bpf_map *map1, struct bpf_map *map2, int *num_return_keys, int phi);

#endif
