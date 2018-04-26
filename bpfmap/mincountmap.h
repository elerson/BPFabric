#ifndef __EBPF_MINCOUNTMAP_H
#define __EBPF_MINCOUNTMAP_H

#include "bpfmap.h"

struct bpf_map *mincountmap_map_alloc(union bpf_attr *attr);
void mincountmap_map_free(struct bpf_map *map);
void *mincountmap_map_lookup_elem(struct bpf_map *map, void *key);
int mincountmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int mincountmap_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int mincountmap_map_delete_elem(struct bpf_map *map, void *key);

#endif
