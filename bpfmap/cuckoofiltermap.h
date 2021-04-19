#ifndef __EBPF_CUCKOOFILTER_H
#define __EBPF_CUCKOOFILTER_H

#include "bpfmap.h"

struct bpf_map *cuckoofilter_map_alloc(union bpf_attr *attr);
void cuckoofilter_map_free(struct bpf_map *map);
void *cuckoofilter_map_lookup_elem(struct bpf_map *map, void *key);
int cuckoofilter_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int cuckoofilter_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int cuckoofilter_map_delete_elem(struct bpf_map *map, void *key);
int cuckoofilter_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag);


#endif
