#ifndef __EBPF_PCSAMAP_H
#define __EBPF_PCSAMAP_H

#include "bpfmap.h"

struct bpf_map *pcsa_map_alloc(union bpf_attr *attr);
void pcsa_map_free(struct bpf_map *map);
void *pcsa_map_lookup_elem(struct bpf_map *map, void *key);
int pcsa_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int pcsa_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int pcsa_map_delete_elem(struct bpf_map *map, void *key);

#endif
