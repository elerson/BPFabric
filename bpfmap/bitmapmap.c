#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#define DEBUG_ENV 1

#include "bitmapmap.h"
#include "libghthash/ght_hash_table.h"

uint32_t bitmaphash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *bitmap_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *bitmap;
    uint64_t array_size;
    uint32_t elem_size;
   
    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size == 0 ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    elem_size = ((attr->value_size-1)/(sizeof(uint32_t)*8) + 1)*sizeof(uint32_t);
    /* allocate the bitmap structure*/
    bitmap = malloc(attr->max_entries * elem_size*sizeof(uint32_t) + sizeof(uint32_t) + sizeof(*bitmap));
    
    if (!bitmap) {
        errno = ENOMEM;
        return NULL;
    }
    
#ifdef DEBUG_ENV
   saveLog("/tmp/BITMAP", attr->max_entries * elem_size*sizeof(uint32_t) );
#endif

    //printf("teste\n");

    /* copy mandatory map attributes */
    bitmap->map.map_type = attr->map_type;
    bitmap->map.key_size = sizeof(uint32_t);
    bitmap->map.value_size = elem_size;
    bitmap->map.max_entries = attr->max_entries;

    bitmap->elem_size = attr->key_size;

    return &bitmap->map;

}

void bitmap_map_free(struct bpf_map *map)
{
    struct bpf_array  *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

void *bitmap_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value, i;

    uint32_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);

    uint32_t* ret = (uint32_t*) array->value;// calloc(1, sizeof(uint32_t));
    *ret = 1;
    for (index = 0; index < array->map.max_entries; index++ ){
    	//ptr = (uint32_t*) array->value + sizeof(uint32_t) + array->map.value_size*index;
    	ptr = &((uint32_t*) (array->value + sizeof(uint32_t)))[array->map.value_size*index];
    	for (i = 0; i < array->elem_size; i++)
        {
    	    hash_value = bitmaphash(*((uint32_t*) key), index, i)%(array->map.value_size*sizeof(uint32_t)*8);
            //printf("hash %d key %d \n", hash_value, *((uint32_t*) key));
    	    *ret &= (ptr[hash_value/(sizeof(uint32_t)*8)] & (0x1 << (hash_value%(sizeof(uint32_t)*8)))) != 0;
        }
        //printf("\n");
    }
    //printf("found %d\n", *ret);
    return ret;
}

int bitmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int bitmap_map_update_elem(struct bpf_map *map, void *key, void *value,
                 uint64_t map_flags)
{
    //printf("update %d %d\n", *((uint32_t*) key), map_flags);
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
   
    //Clean the bitmap fields 
    uint32_t i, index;
    uint32_t hash_value;
    uint32_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    if(map_flags == BPF_CLEAN)
    {
    
    	 memset(array->value, 0, array->map.max_entries*array->map.value_size*sizeof(uint32_t) +  sizeof(*array) + sizeof(uint32_t));
        /*for (index = 0; index < array->map.max_entries; index++ )
        {   
            ptr = (uint32_t*) array->value + sizeof(uint32_t) + array->map.value_size*index;
            for (i = 0; i < array->map.value_size/sizeof(uint32_t); i++)
            {
                ptr[i] = 0;            
            }
        }*/
        return 0;
    }


    for (index = 0; index < array->map.max_entries; index++ ){
        //ptr = (uint32_t*) array->value + sizeof(uint32_t) + array->map.value_size*index;
        ptr = &((uint32_t*) (array->value + sizeof(uint32_t)))[array->map.value_size*index];
        for (i = 0; i < array->elem_size; i++)
        {
            hash_value = bitmaphash(*((uint32_t*) key), index, i)%(array->map.value_size*sizeof(uint32_t)*8);
            //hash_value = bitmaphash(*((uint32_t*) key), index, i)%(array->map.value_size*8);
            //printf("hash %d key %d \n", hash_value, *((uint32_t*) key));
            ptr[hash_value/(sizeof(uint32_t)*8)] |= (0x1 << (hash_value%(sizeof(uint32_t)*8)));
        }
    }
    return 0;
}

int bitmap_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}
