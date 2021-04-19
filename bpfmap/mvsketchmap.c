#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "map/map.h"

#include "mvsketchmap.h"
#include "libghthash/ght_hash_table.h"
//#include "heap_sort.h"
#include "utils.h"
#define DEBUG_ENV 1

#define MAX_RETURN_KEYS 10000



struct return_keys{
  uint32_t key[MAX_RETURN_KEYS];
};

struct mvdata
{
    uint32_t K;
    int64_t V;
    int64_t C;    
};



uint32_t mvhash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    //printf("hh %d\n", key);
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *mvsketch_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *mvsketchmap;
    uint64_t array_size;
    uint32_t elem_size;
   
    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size == 0 ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    elem_size = attr->value_size*sizeof(struct mvdata);
    /* allocate the mincountmap structure*/
    //mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    
    mvsketchmap = malloc((attr->max_entries) * elem_size + sizeof(struct bpf_array) + sizeof(struct return_keys));
    //memset(mincountmap, 0, attr->max_entries * elem_size + sizeof(*mincountmap));
    if (!mvsketchmap) {
        errno = ENOMEM;
        return NULL;
    }
    
#ifdef DEBUG_ENV
   saveLog("/tmp/MVSKETCH", (attr->max_entries) * elem_size);
#endif

    //printf("size %d %d %p %d\n", attr->max_entries , attr->value_size, mincountmap->value, ((mincountmap->value + attr->value_size*attr->max_entries*sizeof(int64_t))-mincountmap->value)/sizeof(int64_t));
    /* copy mandatory map attributes */
    mvsketchmap->map.map_type = attr->map_type;
    mvsketchmap->map.key_size = sizeof(uint32_t);
    mvsketchmap->map.value_size = elem_size;
    mvsketchmap->map.max_entries = attr->max_entries;

    mvsketchmap->elem_size = attr->key_size;

    return &mvsketchmap->map;

}

void mvsketch_map_free(struct bpf_map *map)
{
    struct bpf_array *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

void *mvsketch_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value, i, j;
    
   

    struct mvdata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct mvdata);

    uint32_t *mvret = (uint32_t*) array->value;
    *mvret = 0xFFFFFFFF;

    for (index = 0; index < array->map.max_entries; index++ )
    {
        ptr = &((struct mvdata*) (array->value + sizeof(struct return_keys)))[num_elements*index];
        for (i = 0; i < array->elem_size; i++)
        {
            hash_value = mvhash(*((uint32_t*) key), index, i);            
            hash_value = hash_value%(num_elements);
           
            if(ptr[hash_value].K == *((uint32_t*) key)){
                int value = (ptr[hash_value].V + ptr[hash_value].C)/2;
                *mvret = *mvret < value ? *mvret : value;
            }else{
                int value = (ptr[hash_value].V - ptr[hash_value].C)/2;
                *mvret = *mvret < value ? *mvret : value;
            }
        }
    }

    return mvret;
}

int mvsketch_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int mvsketch_map_update_elem(struct bpf_map *map, void *key, void *value,
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
    struct mvdata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct mvdata);
    
    
    //printf("(%d)", (value));
    if(map_flags == BPF_CLEAN)
    {   printf("clean \n");
        memset(array->value, 0, sizeof(struct return_keys) + array->map.max_entries*num_elements*sizeof(struct mvdata));
        /*for (index = 0; index < array->map.max_entries; index++ )
        {   
            ptr = (int64_t*) array->value + array->map.value_size*index;
            for (i = 0; i < num_elements; i++)
            {
                ptr[i] = 0;            
            }
        }*/
        return 0;
    }
   
    //printf("update %p\n", array->value);
    for (index = 0; index < array->map.max_entries; index++ ){
        ptr = &((struct mvdata*) (array->value + sizeof(struct return_keys)))[num_elements*index];
        for (i = 0; i < array->elem_size; i++){
           
            hash_value = mvhash(*((uint32_t*) key), index, i);
            hash_value = hash_value%(num_elements);
            //printf("lookup (Key %d) %d\n", *((int*) key), hash_value);
            ptr[hash_value].V += *((int32_t*)value);

            if(ptr[hash_value].K == *((uint32_t*) key)){
                ptr[hash_value].C += *((int32_t*)value);
            }else{
                ptr[hash_value].C -= *((int32_t*)value);
                if(ptr[hash_value].C < 0){
                    ptr[hash_value].K = *((uint32_t*) key);
                    ptr[hash_value].C = -ptr[hash_value].C;
                }
            }            
        }
    }
    
    return 0;
}

int mvsketch_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}

int mvsketch_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag)
{
    struct bpf_array *array_dst = container_of(map_dest, struct bpf_array, map);
    struct bpf_array *array_src1 = container_of(map_src1, struct bpf_array, map);
    struct bpf_array *array_src2 = container_of(map_src2, struct bpf_array, map);
 
    uint32_t i, index;
    struct mvdata *ptr_dst, *ptr_src1, *ptr_src2;
    uint num_elements = array_dst->map.value_size/sizeof(struct mvdata);

    //printf("%d %d \n", map_src1, num_elements);
    for (index = 0; index < array_src1->map.max_entries; index++ )
    {   
        ptr_dst  = &((struct mvdata*) (array_dst->value  + sizeof(struct return_keys)))[num_elements*index]; //(int64_t*) array_dst->value  + array_dst->map.value_size*index;
        ptr_src1 = &((struct mvdata*) (array_src1->value + sizeof(struct return_keys)))[num_elements*index]; //int64_t*) array_src1->value + array_src1->map.value_size*index;
        ptr_src2 = &((struct mvdata*) (array_src2->value + sizeof(struct return_keys)))[num_elements*index];  //(int64_t*) array_src2->value + array_src2->map.value_size*index;

          
        //printf("diff %d\n", index);
        for (i = 0; i < num_elements; i++)
        {
            if(ptr_src1[i].K == ptr_src2[i].K){
                ptr_dst[i].K = ptr_src2[i].K;
                ptr_dst[i].V = abs(ptr_src1[i].V - ptr_src2[i].V);
                ptr_dst[i].C = abs(ptr_src1[i].C - ptr_src2[i].C);
            }else{
                ptr_dst[i].K = ptr_src1[i].K;
                ptr_dst[i].V = abs(ptr_src1[i].V);
                ptr_dst[i].C = abs(ptr_src1[i].C);
            }
        }
    }
    //printf("\n\n\n\n\n\n\n\n");

    return 0;
}

void* mvsketch_map_heavy_key_elem(struct bpf_map *map, int *num_return_keys, int phi){
    uint32_t i, j, index;
    uint32_t hash_value;
    struct mvdata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct mvdata);

    map_int_t keys_map;
    map_init(&keys_map);
    char local_key[5];
    for (index = 0; index < array->map.max_entries; index++ ){
        ptr = &((struct mvdata*) (array->value + sizeof(struct return_keys)))[num_elements*index];
        for (i = 0; i < num_elements; i++){
            if(ptr[i].K == 0)
                continue;
            uint_to_char(ptr[i].K, local_key);
            int *val = map_get(&keys_map, local_key);
            if(val){
                continue;
            }
        
            uint32_t *ret_map = mvsketch_map_lookup_elem(map, &(ptr[i].K));
            if(*ret_map > phi){
               map_set(&keys_map, local_key, *ret_map);
            }else{
               map_set(&keys_map, local_key, 0);
            }
        }
    }
    
    int num_keys = 0;
    
    map_iter_t iter = map_iter(&keys_map);
    const char *find_key;
    while ((find_key = map_next(&keys_map, &iter))) {
        int *val = map_get(&keys_map, find_key);
        if(*val < phi) continue;
        uint32_t key = char_to_uint(find_key);
        ((uint32_t*) array->value)[num_keys] = key;
        num_keys++;
        if(num_keys >= MAX_RETURN_KEYS) break;
    }
    map_deinit(&keys_map);
    *num_return_keys = num_keys;
     return (void*) array->value; 
}

void* mvsketch_map_heavy_change_elem(struct bpf_map *map1, struct bpf_map *map2, int *num_return_keys, int phi){

   uint32_t i, j, index;
    uint32_t hash_value;
    struct mvdata *ptr;
    struct bpf_array *array = container_of(map1, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct mvdata);

    map_int_t keys_map;
    map_init(&keys_map);
    char local_key[5];
    for (index = 0; index < array->map.max_entries; index++ ){
        ptr = &((struct mvdata*) (array->value + sizeof(struct return_keys)))[num_elements*index];
        for (i = 0; i < num_elements; i++){
            if(ptr[i].K == 0)
                continue;
            uint_to_char(ptr[i].K, local_key);
            int *val = map_get(&keys_map, local_key);
            if(val){
                continue;
            }
            uint32_t *ret_map1 = mvsketch_map_lookup_elem(map1, &(ptr[i].K));
            uint32_t *ret_map2 = mvsketch_map_lookup_elem(map2, &(ptr[i].K));
            if(abs(*ret_map2-*ret_map1) >= phi){
               map_set(&keys_map, local_key, abs(*ret_map2-*ret_map1));
            }else{
               map_set(&keys_map, local_key, 0);
            }
        }
    }
    
    int num_keys = 0;
    
    map_iter_t iter = map_iter(&keys_map);
    const char *find_key;
    while ((find_key = map_next(&keys_map, &iter))) {
        int *val = map_get(&keys_map, find_key);
        if(*val < phi) continue;
       
        uint32_t key = char_to_uint(find_key);

        ((uint32_t*) array->value)[num_keys] = key;
        num_keys++;
        if(num_keys >= MAX_RETURN_KEYS) break;
    }
    map_deinit(&keys_map);
    *num_return_keys = num_keys;
     return (void*) array->value; 


}

