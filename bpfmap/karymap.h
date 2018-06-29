#ifndef __EBPF_KARYMAP_H
#define __EBPF_KARYMAP_H

#include "bpfmap.h"

struct bpf_map *kary_map_alloc(union bpf_attr *attr);
void kary_map_free(struct bpf_map *map);
void *kary_map_lookup_elem(struct bpf_map *map, void *key);
int kary_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int kary_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int kary_map_delete_elem(struct bpf_map *map, void *key);
int kary_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag);


#endif
