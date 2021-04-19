#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "utils.h"
#define DEBUG_ENV 1

#include "mincountmap.h"
#include "libghthash/ght_hash_table.h"


uint32_t mincounthash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *mincountmap_map_alloc(union bpf_attr *attr)
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
    //mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    mincountmap = malloc(attr->max_entries * elem_size + sizeof(*mincountmap) + sizeof(uint32_t));
    
    if (!mincountmap) {
        errno = ENOMEM;
        return NULL;
    }

#ifdef DEBUG_ENV
   saveLog("/tmp/MINCOUNT", attr->max_entries * elem_size );
#endif

    /* copy mandatory map attributes */
    mincountmap->map.map_type = attr->map_type;
    mincountmap->map.key_size = sizeof(uint32_t);
    mincountmap->map.value_size = elem_size;
    mincountmap->map.max_entries = attr->max_entries;

    mincountmap->elem_size = attr->key_size;

    return &mincountmap->map;

}

void mincountmap_map_free(struct bpf_map *map)
{
    struct bpf_array *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

void *mincountmap_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value, i;
    
    
    uint32_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(uint32_t);

    uint32_t* ret = (uint32_t*) array->value;//calloc(1, sizeof(uint32_t));
    *ret = 0xFFFFFFFF;

    for (index = 0; index < array->map.max_entries; index++ ){
    	//ptr = (uint32_t*) array->value + sizeof(uint32_t) + array->map.value_size*index;
    	ptr = &((uint32_t*) (array->value + sizeof(uint32_t)))[num_elements*index];
    	for (i = 0; i < array->elem_size; i++)
        {
    	    hash_value = mincounthash(*((uint32_t*) key), index, i)%(num_elements);            
    	    *ret = *ret < ptr[hash_value]? *ret : ptr[hash_value];
    	    //printf("look hash %d key %d ptr %p %d %d %d %d \n", hash_value, *((uint32_t*) key), ptr, index, num_elements, i, ptr[hash_value]);
        }
        //printf("\n");
    }
    //printf("found %d\n", *ret);
    return ret;
}

int mincountmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int mincountmap_map_update_elem(struct bpf_map *map, void *key, void *value,
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
    //printf("(%d)", (map_flags));
    
    if(map_flags == BPF_CLEAN)
    {   
        printf("clean %d\n", array->map.max_entries);
        //clock_t start, end;
        //double cpu_time_used;
     
        //start = clock();
     
     
        memset(array->value, 0, array->map.max_entries*num_elements*sizeof(uint32_t) +  sizeof(*array) + sizeof(uint32_t));
        //end = clock();
        //cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

        //printf("cleaned %f\n", cpu_time_used);
        
        /*for (index = 0; index < array->map.max_entries; index++ )
        {   
            ptr = (uint32_t*) array->value + array->map.value_size*index;
            for (i = 0; i < num_elements; i++)
            {
                ptr[i] = 0;            
            }
        }*/
        return 0;
    }
    
   
    
    for (index = 0; index < array->map.max_entries; index++ ){
        //ptr = (uint32_t*) array->value + sizeof(uint32_t) + array->map.value_size*index;
        ptr = &((uint32_t*) (array->value + sizeof(uint32_t)))[num_elements*index];
        for (i = 0; i < array->elem_size; i++)
        {
            hash_value = mincounthash(*((uint32_t*) key), index, i)%(num_elements);
            
            //printf("lookup hash %d \n", hash_value);
            ptr[hash_value] += 1;//*((int*) value);
            //printf("look hash %d key %d ptr %p %d %d %d \n", hash_value, *((uint32_t*) key), ptr, index, num_elements, i);
            
        }
    }
    return 0;
}

int mincountmap_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}
