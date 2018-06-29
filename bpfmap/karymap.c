#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "karymap.h"
#include "libghthash/ght_hash_table.h"


uint32_t karyhash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *kary_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *mincountmap;
    uint64_t array_size;
    uint32_t elem_size;
   
    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size == 0 ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    elem_size = attr->value_size*sizeof(uint32_t);
    /* allocate the mincountmap structure*/
    mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    
    if (!mincountmap) {
        errno = ENOMEM;
        return NULL;
    }

    /* copy mandatory map attributes */
    mincountmap->map.map_type = attr->map_type;
    mincountmap->map.key_size = sizeof(uint32_t);
    mincountmap->map.value_size = elem_size;
    mincountmap->map.max_entries = attr->max_entries;

    mincountmap->elem_size = attr->key_size;

    return &mincountmap->map;

}

void kary_map_free(struct bpf_map *map)
{
    struct bpf_array *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

void *kary_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value, i;
    
    uint32_t* ret = calloc(1, sizeof(uint32_t));
    *ret = 0xFFFFFFFF;
    uint32_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(uint32_t);

    for (index = 0; index < array->map.max_entries; index++ ){
    	ptr = (uint32_t*) array->value + array->map.value_size*index;
    	for (i = 0; i < array->elem_size; i++)
        {
    	    hash_value = karyhash(*((uint32_t*) key), index, i)%(num_elements);
            //printf("hash %d key %d \n", hash_value, *((uint32_t*) key));
    	    *ret = *ret < ptr[hash_value]? *ret : ptr[hash_value];
        }
        //printf("\n");
    }
    //printf("found %d\n", *ret);
    return ret;
}

int kary_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int kary_map_update_elem(struct bpf_map *map, void *key, void *value,
                 uint64_t map_flags)
{
    //printf("update (%d)\n", map_flags);
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
   
    //Clean the mincountmap fields 
    uint32_t i, index;
    uint32_t hash_value;
    uint32_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(uint32_t);
    //printf("(%d)", (value));
    if(map_flags == BPF_CLEAN)
    {   printf("clean \n");
        for (index = 0; index < array->map.max_entries; index++ )
        {   
            ptr = (uint32_t*) array->value + array->map.value_size*index;
            for (i = 0; i < num_elements; i++)
            {
                ptr[i] = 0;            
            }
        }
        return 0;
    }

    
    for (index = 0; index < array->map.max_entries; index++ ){
        ptr = (uint32_t*) array->value + array->map.value_size*index;
        for (i = 0; i < array->elem_size; i++)
        {
            hash_value = karyhash(*((uint32_t*) key), index, i)%(num_elements);
            ptr[hash_value] += *((int*) value);
        }
    }
    return 0;
}

int kary_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}

int kary_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag)
{
    struct bpf_array *array_dst = container_of(map_dest, struct bpf_array, map);
    struct bpf_array *array_src1 = container_of(map_src1, struct bpf_array, map);
    struct bpf_array *array_src2 = container_of(map_src2, struct bpf_array, map);
 
    uint32_t i, index;
    uint32_t *ptr_dst, *ptr_src1, *ptr_src2;
    uint num_elements = array_dst->map.value_size/sizeof(uint32_t);


    for (index = 0; index < array_dst->map.max_entries; index++ )
    {   
        ptr_dst  = (uint32_t*) array_dst->value  + array_dst->map.value_size*index;
        ptr_src1 = (uint32_t*) array_src1->value + array_src1->map.value_size*index;
        ptr_src2 = (uint32_t*) array_src2->value + array_src2->map.value_size*index;


        for (i = 0; i < num_elements; i++)
        {
            ptr_dst[i] = ptr_src1[i] - ptr_src2[i];            
        }
    }

    return 0;
}
