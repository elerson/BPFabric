#include <sys/queue.h>
#include <string.h>

#include "bpfmap.h"
#include "arraymap.h"
#include "hashtab.h"
#include "bitmapmap.h"
#include "mincountmap.h"
#include "pcsamap.h"
#include "karymap.h"
#include "mvsketchmap.h"
#include "elasticmap.h"
#include "cuckoofiltermap.h"
#include "ldsketchmap.h"
#include "foo_map.h"

#define MAX_MAPS 64
#define BPF_MAP_TYPE_BITMAP 5
#define BPF_MAP_TYPE_MINCOUNT 6
#define BPF_MAP_TYPE_MVSKETCH 9
#define BPF_MAP_TYPE_ELASTIC 10
#define BPF_MAP_TYPE_CUCKOO 11
#define BPF_MAP_TYPE_LDSKETCH 12

struct bpf_map *bpf_maps[MAX_MAPS] = {0};


const struct bpf_map_ops bpf_map_types[] = {
    [BPF_MAP_TYPE_HASH] = {
        .map_alloc = htab_map_alloc,
        .map_free = htab_map_free,
        .map_get_next_key = htab_map_get_next_key,
        .map_lookup_elem = htab_map_lookup_elem,
        .map_update_elem = htab_map_update_elem,
        .map_delete_elem = htab_map_delete_elem,
    },
    [BPF_MAP_TYPE_ARRAY] = {
        .map_alloc = array_map_alloc,
        .map_free = array_map_free,
        .map_get_next_key = array_map_get_next_key,
        .map_lookup_elem = array_map_lookup_elem,
        .map_update_elem = array_map_update_elem,
        .map_delete_elem = array_map_delete_elem,
    },
    [BPF_MAP_TYPE_PROG_ARRAY] = {
        .map_alloc = NULL,
        .map_free = NULL,
        .map_get_next_key = NULL,
        .map_lookup_elem = NULL,
        .map_update_elem = NULL,
        .map_delete_elem = NULL,
    },
    [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = {
        .map_alloc = NULL,
        .map_free = NULL,
        .map_get_next_key = NULL,
        .map_lookup_elem = NULL,
        .map_update_elem = NULL,
        .map_delete_elem = NULL,
    },
    [BPF_MAP_TYPE_BITMAP] = {
        .map_alloc = bitmap_map_alloc,
        .map_free = bitmap_map_free,
        .map_get_next_key = bitmap_map_get_next_key,
        .map_lookup_elem = bitmap_map_lookup_elem,
        .map_update_elem = bitmap_map_update_elem,
        .map_delete_elem = bitmap_map_delete_elem,
    },
    [BPF_MAP_TYPE_MINCOUNT] = {
        .map_alloc = mincountmap_map_alloc,
        .map_free  = mincountmap_map_free,
        .map_get_next_key = mincountmap_map_get_next_key,
        .map_lookup_elem = mincountmap_map_lookup_elem,
        .map_update_elem = mincountmap_map_update_elem,
        .map_delete_elem = mincountmap_map_delete_elem,
    },

    [BPF_MAP_TYPE_PCSA] = {
        .map_alloc = pcsa_map_alloc,
        .map_free  = pcsa_map_free,
        .map_get_next_key = pcsa_map_get_next_key,
        .map_lookup_elem = pcsa_map_lookup_elem,
        .map_update_elem = pcsa_map_update_elem,
        .map_delete_elem = pcsa_map_delete_elem,
    },


    [BPF_MAP_TYPE_KARY] = {
        .map_alloc = kary_map_alloc,
        .map_free  = kary_map_free,
        .map_get_next_key = kary_map_get_next_key,
        .map_lookup_elem = kary_map_lookup_elem,
        .map_update_elem = kary_map_update_elem,
        .map_delete_elem = kary_map_delete_elem,
        .map_diff_map_elem = kary_map_diff_elem,
    },

    [BPF_MAP_TYPE_MVSKETCH] = {
        .map_alloc = mvsketch_map_alloc,
        .map_free  = mvsketch_map_free,
        .map_get_next_key = mvsketch_map_get_next_key,
        .map_lookup_elem = mvsketch_map_lookup_elem,
        .map_update_elem = mvsketch_map_update_elem,
        .map_delete_elem = mvsketch_map_delete_elem,
        .map_diff_map_elem = mvsketch_map_diff_elem,
        .map_heavy_key_elem = mvsketch_map_heavy_key_elem,
        .map_heavy_change_elem = mvsketch_map_heavy_change_elem
    },
    
    [BPF_MAP_TYPE_ELASTIC] = {
        .map_alloc = elasticmap_map_alloc,
        .map_free  = elasticmap_map_free,
        .map_get_next_key = elasticmap_map_get_next_key,
        .map_lookup_elem = elasticmap_map_lookup_elem,
        .map_update_elem = elasticmap_map_update_elem,
        .map_delete_elem = elasticmap_map_delete_elem,
        .map_heavy_key_elem = elasticmap_map_heavy_key_elem,
        .map_heavy_change_elem = elasticmap_map_heavy_change_elem
    },

    [BPF_MAP_TYPE_CUCKOO] = {
        .map_alloc = cuckoofilter_map_alloc,
        .map_free  = cuckoofilter_map_free,
        .map_get_next_key = cuckoofilter_map_get_next_key,
        .map_lookup_elem = cuckoofilter_map_lookup_elem,
        .map_update_elem = cuckoofilter_map_update_elem,
        .map_delete_elem = cuckoofilter_map_delete_elem
    },
    
   [BPF_MAP_TYPE_LDSKETCH] = {
        .map_alloc = ldsketch_map_alloc,
        .map_free  = ldsketch_map_free,
        .map_get_next_key = ldsketch_map_get_next_key,
        .map_lookup_elem = ldsketch_map_lookup_elem,
        .map_update_elem = ldsketch_map_update_elem,
        .map_delete_elem = ldsketch_map_delete_elem,
        .map_heavy_key_elem = ldsketch_map_heavy_key_elem,
        .map_heavy_change_elem = ldsketch_map_heavy_change_elem
    },

    [BPF_MAP_TYPE_FOO] = {
        .map_alloc = foo_map_alloc,
        .map_free  = foo_map_free,
        .map_lookup_elem = foo_map_lookup_elem,
        .map_update_elem = foo_map_update_elem,
    }
};

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries) {
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;

    //
    const struct bpf_map_ops *map_type_ops = &bpf_map_types[map_type];
    //printf("alloc %x %d %d\n", map_type_ops, map_type, BPF_MAP_TYPE_BITMAP);
    struct bpf_map *map;

    //printf("test 2\n");
    map = map_type_ops->map_alloc(&attr);
    //printf("test 1\n");
    if (map == NULL) {
        return -1;
    }
    //printf("alloc %x\n", map);
    map->ops = map_type_ops;

    // find a free idx for this map
    int map_idx = -1;
    for (int i=0; i < MAX_MAPS; i++) {
        if (bpf_maps[i] == NULL) {
            map_idx = i;
            bpf_maps[map_idx] = map;
            break;
        }
    }
    //printf("id %d\n", map_idx);
    return map_idx;
}

int bpf_update_elem(int map, void *key, void *value, unsigned long long flags) {
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_update_elem(m, key, value, flags);
}

int bpf_lookup_elem(int map, void *key, void *value) {
    void **v = value;
    *v = NULL;

    struct bpf_map *m = bpf_maps[map];
    *v = m->ops->map_lookup_elem(m, key);
    if (*v == NULL) {
        return -1;
    }

    return 0;
}

int bpf_diff_elem(int map_dst, int map_src1, int map_src2, int flags) {
    struct bpf_map *m_dst  = bpf_maps[map_dst];
    struct bpf_map *m_src1 = bpf_maps[map_src1];
    struct bpf_map *m_src2 = bpf_maps[map_src2];
    return m_dst->ops->map_diff_map_elem(m_dst, m_src1, m_src2, flags);
}


uint64_t bpf_heavy_key_elem(int map, void *keys, int phi) {
    struct bpf_map *m_src  = bpf_maps[map];
    return (uint64_t) m_src->ops->map_heavy_key_elem(m_src, keys, phi);
}


uint64_t bpf_heavy_change_elem(int map1, int map2, void *keys, int phi){
    struct bpf_map *m_src_1  = bpf_maps[map1];
    struct bpf_map *m_src_2  = bpf_maps[map2];
    return (uint64_t)  m_src_1->ops->map_heavy_change_elem(m_src_1, m_src_2, keys, phi);
}

int bpf_delete_elem(int map, void *key) {
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_delete_elem(m, key);
}

int bpf_get_next_key(int map, void *key, void *next_key) {
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_get_next_key(m, key, next_key);
}
