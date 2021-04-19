#ifndef __EBPF_MVSKETCH_H
#define __EBPF_MVSKETCH_H

#include "bpfmap.h"

struct bpf_map *mvsketch_map_alloc(union bpf_attr *attr);
void mvsketch_map_free(struct bpf_map *map);
void *mvsketch_map_lookup_elem(struct bpf_map *map, void *key);
int mvsketch_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int mvsketch_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int mvsketch_map_delete_elem(struct bpf_map *map, void *key);
int mvsketch_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag);
void* mvsketch_map_heavy_key_elem(struct bpf_map *map, int *num_return_keys, int phi);
void* mvsketch_map_heavy_change_elem(struct bpf_map *map1, struct bpf_map *map2, int *num_return_keys, int phi);

#endif
