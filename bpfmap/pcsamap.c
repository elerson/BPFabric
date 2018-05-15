#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include "pcsamap.h"
#include "libghthash/ght_hash_table.h"

#define U32_MAX 0xFFFFFFFF

uint64_t pcsahash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);


    uint32_t new_key2 = (key)*23 + param1*131 + 11*param2;
    ght_hash_key_t p_key2;
    p_key2.p_key = &new_key2;
    p_key2.i_size = sizeof(uint32_t);

    uint64_t key2 = ght_one_at_a_time_hash(&p_key2);
    key2 <<= 32;

    return ght_one_at_a_time_hash(&p_key) |  key2;
}


uint32_t hash2(uint32_t key, uint32_t M){
    ght_hash_key_t p_key;
    p_key.p_key = &key;
    p_key.i_size = sizeof(uint32_t);
    return ght_one_at_a_time_hash(&p_key) % M;
}

uint64_t R(uint64_t x){
    return ~x & (x+1);
}

uint64_t r(uint64_t x){
    return log2(R(x));
}

struct bpf_map *pcsa_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *pcsa;
    uint64_t array_size;
    uint32_t elem_size;
   
    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size != sizeof(uint32_t) ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    elem_size = sizeof(uint64_t);
    /* allocate the pcsa structure*/
    pcsa = calloc(attr->max_entries * elem_size, sizeof(*pcsa));
    
    if (!pcsa) {
        errno = ENOMEM;
        return NULL;
    }

    //printf("teste\n");

    /* copy mandatory map attributes */
    pcsa->map.map_type = attr->map_type;
    pcsa->map.key_size = sizeof(uint32_t);
    pcsa->map.value_size = elem_size;
    pcsa->map.max_entries = attr->max_entries;

    pcsa->elem_size = elem_size;

    return &pcsa->map;

}

void pcsa_map_free(struct bpf_map *map)
{
    struct bpf_array  *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

void *pcsa_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value, i, sum;
    uint32_t* ret = calloc(1, sizeof(uint32_t));
    uint64_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    sum = 0;
    for (index = 0; index < array->map.max_entries; index++ ){
    	ptr = (uint64_t*) array->value + sizeof(uint64_t)*index;
        sum += r(*ptr);
        //printf("%d %d\n", r(*ptr), *ptr);
    }

    double mean = 1.0 * sum/array->map.max_entries;
    double phi = .77351;
    *ret = (int) (array->map.max_entries * pow(2, mean)/phi);
    return ret;
}

int pcsa_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int pcsa_map_update_elem(struct bpf_map *map, void *key, void *value,
                 uint64_t map_flags)
{
    //printf("update %d\n", *((uint32_t*) key));
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
   
    //Clean the pcsa fields 
    uint32_t i, index;
    uint32_t hash_value;
    uint64_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    if(map_flags == BPF_CLEAN)
    {
        for (index = 0; index < array->map.max_entries; index++ )
        {   
            ptr = (uint64_t*) array->value + array->map.value_size*index;           
            *ptr = 0;            

        }
        return 0;
    }


    index = hash2(*((uint32_t*) key), array->map.max_entries);
    ptr = (uint64_t*) array->value + sizeof(uint64_t)*index;

    //printf("add index %d  key %d %d %d\n", index, *((uint32_t*) key), R(pcsahash(*((uint32_t*) key), index, 0)), pcsahash(*((uint32_t*) key), index, 0));
    *ptr = *ptr | R(pcsahash(*((uint32_t*) key), index, 0));
    //printf("%d, \n", *ptr);
    return 0;
}

int pcsa_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}
