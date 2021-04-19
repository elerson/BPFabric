#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "cuckoofiltermap.h"
#include "libghthash/ght_hash_table.h"
//#include "heap_sort.h"

#include "utils.h"
#define DEBUG_ENV 1

#define MaxNumKicks 20

#define bool unsigned char
#define true 1
#define false 0

struct cukoodata
{
    uint32_t K;
    int32_t V;
};

void swap_cuckoo_filter(struct cukoodata *data_1, struct cukoodata *data_2){
    struct cukoodata tmp;
    tmp.K = data_1->K;
    tmp.V = data_1->V;

    data_1->K = data_2->K;
    data_1->V = data_2->V;

    data_2->K = tmp.K;
    data_2->V = tmp.V;
}

bool insert_cuckoo_filter(struct cukoodata *data, struct cukoodata *ptr, int max_entries){
    for(int i = 0; i < max_entries; ++i){
        if(ptr[i].K == 0 || ptr[i].K == data->K){
            ptr[i].K = data->K;
            ptr[i].V = data->V;
            return true;
        }
    }
    return false;
}


bool remove_cuckoo_filter(struct cukoodata *data, struct cukoodata *ptr, int max_entries){
    for(int i = 0; i < max_entries; ++i){
        if(ptr[i].K == data->K){    
            ptr[i].K = 0;
            return true;
        }
    }
    return false;
}


bool find_cuckoo_filter(struct cukoodata *data, struct cukoodata *ptr, int max_entries){
    for(int i = 0; i < max_entries; ++i){
        if(ptr[i].K == data->K){            
            data->V = ptr[i].V;
            return true;
        }
    }
    return false;
}


uint32_t cuckoofilterhash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    //printf("hh %d\n", key);
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *cuckoofilter_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *cukoomap;
    uint64_t array_size;
    uint32_t elem_size;
   
    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size == 0 ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    elem_size = attr->value_size*sizeof(struct cukoodata);
    /* allocate the mincountmap structure*/
    //mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    
    cukoomap = malloc(attr->max_entries*elem_size + sizeof(struct bpf_array) + sizeof(int32_t));
    //memset(mincountmap, 0, attr->max_entries * elem_size + sizeof(*mincountmap));
    if (!cukoomap) {
        errno = ENOMEM;
        return NULL;
    }

#ifdef DEBUG_ENV
   saveLog("/tmp/CUCKOOFILTER", attr->max_entries*elem_size );
#endif

    //printf("size %d %d %p %d\n", attr->max_entries , attr->value_size, mincountmap->value, ((mincountmap->value + attr->value_size*attr->max_entries*sizeof(int64_t))-mincountmap->value)/sizeof(int64_t));
    /* copy mandatory map attributes */
    cukoomap->map.map_type = attr->map_type;
    cukoomap->map.key_size = sizeof(struct cukoodata);
    cukoomap->map.value_size = elem_size;
    cukoomap->map.max_entries = attr->max_entries;

    cukoomap->elem_size = attr->key_size;

    return &cukoomap->map;

}

void cuckoofilter_map_free(struct bpf_map *map)
{
    struct bpf_array *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

void *cuckoofilter_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value1, hash_value2, i, j;
    

    struct cukoodata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct cukoodata);

    int32_t *mvret = (int32_t*) array->value;
    *mvret = 0xFFFFFFFF;


    struct cukoodata data, *temp;
    data.K = *((uint32_t*) key);

    //printf("update %p\n", array->value);
    ptr = (struct cukoodata*) array->value + sizeof(int32_t);
    
    hash_value1 = cuckoofilterhash(*((uint32_t*) key), 0, 0);
    hash_value1 = (hash_value1%(num_elements))*array->map.max_entries;

    hash_value2 = cuckoofilterhash(*((uint32_t*) key), 1, 1);
    hash_value2 = (hash_value2%(num_elements))*array->map.max_entries;

    if(find_cuckoo_filter(&data, &ptr[hash_value1], array->map.max_entries)){
        *mvret = data.V;
    }else if(find_cuckoo_filter(&data, &ptr[hash_value2], array->map.max_entries)){
        *mvret = data.V;
    }


    return mvret;
}

int cuckoofilter_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}


int cuckoofilter_map_update_elem(struct bpf_map *map, void *key, void *value,
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
    uint32_t hash_value1, hash_value2;
    struct cukoodata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct cukoodata);
    
    
    //printf("(%d)", (value));
    if(map_flags == BPF_CLEAN)
    {   printf("clean \n");
        memset(array->value, 0, sizeof(int32_t) + array->map.max_entries*num_elements*sizeof(struct cukoodata));
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
    
    struct cukoodata data, *temp;
    data.K = *((uint32_t*) key);
    data.V = *((int32_t*)value);

    
    //printf("update %p\n", array->value);
    ptr = (struct cukoodata*) array->value + sizeof(int32_t);
    
    hash_value1 = cuckoofilterhash(*((uint32_t*) key), 0, 0);
    hash_value1 = (hash_value1%(num_elements))*array->map.max_entries;

    hash_value2 = cuckoofilterhash(*((uint32_t*) key), 1, 1);
    hash_value2 = (hash_value2%(num_elements))*array->map.max_entries;
    
    if(insert_cuckoo_filter(&data, &ptr[hash_value1], array->map.max_entries)){
        return 0;
    }else if(insert_cuckoo_filter(&data, &ptr[hash_value2], array->map.max_entries)){
        return 0;
    }

    
    for(i = 0; i < MaxNumKicks; ++i){
        
        int entry = rand() % array->map.max_entries;        
        temp = &((struct cukoodata*)(ptr + hash_value2))[entry];

        swap_cuckoo_filter(&data, temp);
        if(data.K == 0)
            return 0;

        hash_value2 = cuckoofilterhash(data.K, 1, 1);
        hash_value2 = (hash_value2%(num_elements))*array->map.max_entries;

        if(insert_cuckoo_filter(&data, &ptr[hash_value2], array->map.max_entries)){
            return 0;
        }
    }
    
    return 0;
}

int cuckoofilter_map_delete_elem(struct bpf_map *map, void *key)
{

    uint32_t index, hash_value1, hash_value2, i, j;
    
    struct cukoodata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct cukoodata);

    struct cukoodata data, *temp;
    data.K = *((uint32_t*) key);


    //printf("update %p\n", array->value);
    ptr = (struct cukoodata*) array->value + sizeof(int32_t);
    
    hash_value1 = cuckoofilterhash(*((uint32_t*) key), 0, 0);
    hash_value1 = (hash_value1%(num_elements))*array->map.max_entries;

    hash_value2 = cuckoofilterhash(*((uint32_t*) key), 1, 1);
    hash_value2 = (hash_value2%(num_elements))*array->map.max_entries;

    if(remove_cuckoo_filter(&data, &ptr[hash_value1], array->map.max_entries)){
       return 1;
    }else if(remove_cuckoo_filter(&data, &ptr[hash_value2], array->map.max_entries)){
        return 1;
    }
    errno = EINVAL;
    return -1;
}

int cuckoofilter_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag)
{
    
}
