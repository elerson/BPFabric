#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "arraymap.h"

struct bpf_bitmap {
    struct bpf_map map;
    uint32_t elem_size;
    uint32_t found;
    uint32_t **bitmap_matrix;
    
};


struct bpf_map *bitmap_map_alloc(union bpf_attr *attr)
{
    struct bpf_bitmap *bitmap;
    uint64_t array_size;
    uint32_t elem_size;
    /* check sanity of attributes */
    /*if (attr->max_entries == 0 || attr->key_size == 0 ||
        (attr->max_entries*attr->value_size)%attr->param_size != 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }
    /* allocate the bitmap structure*/

    bitmap = calloc(1, sizeof(*bitmap));
    /*
    
    if (!bitmap) {
        errno = ENOMEM;
        return NULL;
    }

    elem_size = (attr->key_size-1)/sizeof(uint32_t)*8 + 1;
    bitmap->bitmap_matrix = (uint32_t **)calloc(bitmap->map.max_entries, sizeof(uint32_t*));
    int j;
    for (j = 0; j < attr->max_entries; j++)
        bitmap->bitmap_matrix[j] = (uint32_t *)calloc(elem_size, sizeof(uint32_t));


    if (!bitmap->bitmap_matrix) {
        errno = ENOMEM;
        return NULL;
    }*/


    /* copy mandatory map attributes */
    bitmap->map.map_type = attr->map_type;
    bitmap->map.key_size = attr->key_size;
    bitmap->map.value_size = attr->value_size;
    bitmap->map.max_entries = attr->max_entries;
    /*
    bitmap->map.function_params = attr->function_params;
    bitmap->map.param_size = attr->param_size;
    bitmap->map.function_ptr = attr->function_ptr;*/
    bitmap->elem_size = elem_size;

    return &bitmap->map;
}

void bitmap_map_free(struct bpf_map *map)
{
    struct bpf_bitmap *bitmap = container_of(map, struct bpf_bitmap, map);
    int j;
    for (j = 0; j < bitmap->map.max_entries; j++)
        free(bitmap->bitmap_matrix[j]);
    free(bitmap->bitmap_matrix);
    free(bitmap);
}

void *bitmap_map_lookup_elem(struct bpf_map *map, void *key)
{
    struct bpf_bitmap *bitmap = container_of(map, struct bpf_bitmap, map);

    int j, k;
    uint32_t hash_value ;
    bitmap->found = 1;
    for (j = 0; j < bitmap->map.param_size; j++)
    {        
        k = j/bitmap->map.value_size;
        hash_value = bitmap->map.function_ptr(key, &( ((uint32_t*) bitmap->map.function_params)[j])) % bitmap->map.key_size;
        bitmap->found &= (bitmap->bitmap_matrix[k][hash_value/(sizeof(uint32_t)*8)] & (0x1 << (hash_value%(sizeof(uint32_t)*8)))) != 0;
    }   
    
    return &(bitmap->found);
}

int bitmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int bitmap_map_update_elem(struct bpf_map *map, void *key, void *value,
                 uint64_t map_flags)
{
    struct bpf_bitmap *bitmap = container_of(map, struct bpf_bitmap, map);

    if (map_flags > BPF_EXIST) {
        /* unknown flags */
        errno = EINVAL;
        return -1;
    }

    if (map_flags == BPF_NOEXIST) {
        /* all elements already exist */
        errno = EEXIST;
        return -1;
    }
   

    int j, k;
    uint32_t hash_value ;

    //Clean the bitmap fields
    if(map_flags == BPF_CLEAN)
    {
        for (k = 0; k < bitmap->map.max_entries; k++)
        {
            for (j = 0; j < bitmap->elem_size; j++)
            {        
                bitmap->bitmap_matrix[k][j] = 0;
            }
        }
        return 0;
    }



    //update the bitmap values
    for (j = 0; j < bitmap->map.param_size; j++)
    {        
        k = j/bitmap->map.value_size;
        hash_value = bitmap->map.function_ptr(key, &( ((uint32_t*) bitmap->map.function_params)[j])) % bitmap->map.key_size;
        bitmap->bitmap_matrix[k][hash_value/(sizeof(uint32_t)*8)] |= (0x1 << (hash_value%(sizeof(uint32_t)*8)));
    }   
    

    return 0;
}

int bitmap_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}
