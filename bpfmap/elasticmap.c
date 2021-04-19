#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "map/map.h"

#include "elasticmap.h"
#include "libghthash/ght_hash_table.h"
#include "utils.h"

#define NUM_MINCOUNT_HASH 3
#define LAMBDA 8
#define NRESULTS 100
#define MAX_BUCKET 10
#define bool unsigned char
#define true 1
#define false 0
#define MAX_RETURN_KEYS 10000
#define DEBUG_ENV 1

struct return_keys{
  uint32_t key[MAX_RETURN_KEYS];
};


struct result_data{
   uint32_t key;
   uint32_t val;
};

struct bucket{
   uint32_t K;
   uint32_t positive;
   bool flag;
};

struct heavy_count{
   struct bucket bucket_[MAX_BUCKET];
   uint32_t negative;
};

uint32_t elasticmaphash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *elasticmap_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *elasticmap;
    uint64_t array_size;
    uint32_t mincountsize;
    uint32_t heavycountsize;

   
    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size == 0 ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    mincountsize = attr->value_size*sizeof(uint32_t);
    heavycountsize = attr->key_size*sizeof(struct heavy_count);
    /* allocate the mincountmap structure*/
    //mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    elasticmap = malloc(heavycountsize + attr->max_entries*mincountsize + sizeof(*elasticmap) + sizeof(struct return_keys));

#ifdef DEBUG_ENV
   saveLog("/tmp/ELASTIC_MAP", heavycountsize + attr->max_entries*mincountsize);
#endif
    
    
    if (!elasticmap) {
        errno = ENOMEM;
        return NULL;
    }

    /* copy mandatory map attributes */
    elasticmap->map.map_type = attr->map_type;
    elasticmap->map.key_size = sizeof(uint32_t);
    elasticmap->map.value_size = mincountsize;
    elasticmap->map.max_entries = attr->max_entries;

    elasticmap->elem_size = heavycountsize;

    return &elasticmap->map;

}

void elasticmap_map_free(struct bpf_map *map)
{
    struct bpf_array *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}

bool find_elastic_map(uint32_t key, struct heavy_count *ptr, uint32_t* ret){
   for(int i = 0; i < MAX_BUCKET; ++i){
      if(ptr->bucket_[i].K == key){
         *ret = ptr->bucket_[i].positive;
         
         if(ptr->bucket_[i].flag == true)
            return false;
            
         return true;
      }
   }
   return false;
}

bool insert_elastic_map(uint32_t key, struct heavy_count *ptr, uint32_t* insert_value, uint32_t *insert_key){
   int min_index = 0;
   for(int i = 0; i < MAX_BUCKET; ++i){

       if(ptr->bucket_[i].K == 0){
           ptr->bucket_[i].K = key;
           ptr->bucket_[i].positive = 1;           
           ptr->bucket_[i].flag = false;
           return true;

       }else if(ptr->bucket_[i].K == key){
           ptr->bucket_[i].positive++;
           return true;
       }
       if(ptr->bucket_[i].positive < ptr->bucket_[min_index].positive)
           min_index = i;
   }
   
  
   ptr->negative--;
   if( (ptr->negative/ptr->bucket_[min_index].positive) < LAMBDA){
      *insert_value = 1;
         //insert to CM sketch
   }else{
      *insert_value = ptr->bucket_[min_index].positive;
      *insert_key =  ptr->bucket_[min_index].K;

      ptr->bucket_[min_index].K = key;
      ptr->bucket_[min_index].positive = 1;
      ptr->bucket_[min_index].flag = true;
   }
   
   return false;
}

void *elasticmap_map_lookup_elem(struct bpf_map *map, void *key)
{
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value, i;

    uint32_t* ptr_count;
    struct heavy_count *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    
     uint32_t* ret = (uint32_t*) array->value;
    *ret = 0xFFFFFFFF;
    
    uint num_mincount = array->map.value_size/sizeof(uint32_t);
    uint num_heavycount = array->elem_size/sizeof(struct heavy_count);

    bool look_in_count = true;
    int f1 = elasticmaphash(*((uint32_t*) key), 0, 1)%(num_heavycount);
    ptr = &((struct heavy_count*) (array->value + sizeof(struct return_keys)))[f1];
    //printf("look %d %p \n", f1, ptr);
    uint32_t count_local = 0;
    if(find_elastic_map(*((uint32_t*) key), ptr, &count_local)){
    	look_in_count = false;
    }

    if(!look_in_count){
        *ret = count_local;
        return ret;
    }

    for (index = 0; index < array->map.max_entries; index++ ){
        //ptr = (uint32_t *) array->value + sizeof(uint32_t) + num_heavycount*sizeof(struct heavy_count) + array->map.value_size*index;
        
        ptr_count = &((uint32_t*) (array->value + sizeof(struct return_keys) + num_heavycount*sizeof(struct heavy_count)) )[num_mincount*index];
        //printf("%p \n", ptr_count);
        for (i = 0; i < NUM_MINCOUNT_HASH; i++)
        {
            hash_value = elasticmaphash(*((uint32_t*) key), index, i)%(num_mincount);            
            *ret = *ret < (ptr_count[hash_value] + count_local) ? *ret : (ptr_count[hash_value] + count_local);
            //printf("look hash %d key %d ptr %p %d %d %d %d \n", hash_value, *((uint32_t*) key), ptr, index, num_elements, i, ptr[hash_value]);
        }
        //printf("\n");
    }
    //printf("found %d\n", *ret);
    return ret;
}

int elasticmap_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

int elasticmap_map_update_elem(struct bpf_map *map, void *key, void *value,
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
    uint32_t *ptr_count;
    struct heavy_count *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    //uint num_elements = array->map.value_size/sizeof(uint32_t);
    uint num_mincount = array->map.value_size/sizeof(uint32_t);
    uint num_heavycount = array->elem_size/sizeof(struct heavy_count);
    //printf("(%d)", (map_flags));
    
    if(map_flags == BPF_CLEAN)
    {   //printf("clean %d\n", array->map.max_entries);
        //clock_t start, end;    
        memset(array->value, 0, sizeof(struct return_keys) + array->map.max_entries*num_mincount*sizeof(uint32_t) + num_heavycount*sizeof(struct heavy_count) + sizeof(*array));
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
    
    
    bool insert_in_heavy = false;
    int insert_value = 1;
    uint32_t local_key = *((uint32_t*) key);

    int f1 = elasticmaphash(*((uint32_t*) key), 0, 1)%(num_heavycount);
    ptr = &((struct heavy_count*) (array->value + sizeof(struct return_keys)))[f1];
    //printf("insert %d %p \n", f1, ptr);
    insert_in_heavy = insert_elastic_map(local_key, ptr, &insert_value, &local_key);
    
    if(insert_in_heavy)
        return 0;
    
    
    for (index = 0; index < array->map.max_entries; index++ ){
        //ptr = (uint32_t*) array->value + sizeof(uint32_t) + num_heavycount + array->map.value_size*index;
        ptr_count = &((uint32_t*) (array->value + sizeof(struct return_keys) + num_heavycount*sizeof(struct heavy_count)) )[num_mincount*index];
        for (i = 0; i < NUM_MINCOUNT_HASH; i++)
        {
            hash_value = elasticmaphash(local_key, index, i)%(num_mincount);
            
            //printf("lookup hash %d \n", hash_value);
            ptr_count[hash_value] += insert_value;//*((int*) value);
            //printf("look hash %d key %d ptr %p %d %d %d \n", hash_value, *((uint32_t*) key), ptr, index, num_elements, i);
            
        }
    }
    return 0;
}

void* elasticmap_map_heavy_key_elem(struct bpf_map *map, int *num_return_keys, int phi){
    //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value;

    uint32_t* ptr_count;
    struct heavy_count *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    
    uint num_heavycount = array->elem_size/sizeof(struct heavy_count);
    int num_keys = 0;
    for(int i = 0; i < num_heavycount; ++i){
    	ptr = &((struct heavy_count*) (array->value + sizeof(struct return_keys)))[i];
    	for(int j = 0; j < MAX_BUCKET; ++j){
    	    if(ptr->bucket_[j].positive > phi && ptr->bucket_[j].K > 0){
    	        ((uint32_t*) array->value)[num_keys] = ptr->bucket_[j].K;
    	        num_keys++;
    	        if(num_keys >= MAX_RETURN_KEYS) break;
    	    }
    	}
    	if(num_keys >= MAX_RETURN_KEYS) break;
    }
    *num_return_keys = num_keys;
     return (void*) array->value;   
}

void* elasticmap_map_heavy_change_elem(struct bpf_map *map1, struct bpf_map *map2, int *num_return_keys, int phi){
        //printf("find %d\n", *((uint32_t*) key));
    uint32_t index, hash_value;

    uint32_t* ptr_count;
    struct heavy_count *ptr;
    struct bpf_array *array = container_of(map1, struct bpf_array, map);
    
    uint num_heavycount = array->elem_size/sizeof(struct heavy_count);
    
    map_int_t keys_map;
    map_init(&keys_map);
    char local_key[5];
    
    for(int i = 0; i < num_heavycount; ++i){
    	ptr = &((struct heavy_count*) (array->value + sizeof(struct return_keys)))[i];
    	for(int j = 0; j < MAX_BUCKET; ++j){
    	    if(ptr->bucket_[j].K == 0)
              continue;
              
            uint_to_char(ptr->bucket_[j].K, local_key);

            
            int *val = map_get(&keys_map, local_key);
            if(val){
                continue;
            }
    	    
    	    uint32_t *ret_map2 = elasticmap_map_lookup_elem(map2, &(ptr->bucket_[j].K));
    	    //uint32_t *ret_map1 = elasticmap_map_lookup_elem(map1, &(ptr->bucket_[j].K));
    	    
    	    if(abs(ptr->bucket_[j].positive - *ret_map2) > phi){
    	    	map_set(&keys_map, local_key, abs(ptr->bucket_[j].positive - *ret_map2));    	    
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
        
        if(*val <= phi) continue;
        uint32_t key = char_to_uint(find_key);
        
        printf("%d %d \n", key, *val);
        
        ((uint32_t*) array->value)[num_keys] = key;
        num_keys++;
        if(num_keys >= MAX_RETURN_KEYS) break;
    }
    map_deinit(&keys_map);
    *num_return_keys = num_keys;
     return (void*) array->value; 
}

int elasticmap_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}
