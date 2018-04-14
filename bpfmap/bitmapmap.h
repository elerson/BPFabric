#ifndef __EBPF_BITMAPMAP_H
#define __EBPF_BITMAPMAP_H

#include "bpfmap.h"

struct bpf_map *bitmap_map_alloc(union bpf_attr *attr);
void bitmap_map_free(struct bpf_map *map);
void *bitmap_map_lookup_elem(struct bpf_map *map, void *key);
int bitmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int bitmap_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int bitmap_map_delete_elem(struct bpf_map *map, void *key);

#endif
