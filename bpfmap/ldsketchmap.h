#ifndef __EBPF_LDSKETCH_H
#define __EBPF_LDSKETCH_H

#include "bpfmap.h"

struct bpf_map *ldsketch_map_alloc(union bpf_attr *attr);
void ldsketch_map_free(struct bpf_map *map);
void *ldsketch_map_lookup_elem(struct bpf_map *map, void *key);
int ldsketch_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int ldsketch_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int ldsketch_map_delete_elem(struct bpf_map *map, void *key);
int ldsketch_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag);
void* ldsketch_map_heavy_key_elem(struct bpf_map *map, int *num_return_keys, int phi);
void* ldsketch_map_heavy_change_elem(struct bpf_map *map1, struct bpf_map *map2, int *num_return_keys, int phi);

#endif
