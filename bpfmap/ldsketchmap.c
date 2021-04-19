#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ldsketchmap.h"
#include "libghthash/ght_hash_table.h"
#include "map/map.h"
//#include "heap_sort.h"

#define NUM_L_MAX 100
#define MAX_RETURN_KEYS 10000

#define bool char
#define true 1
#define false 0

struct return_keys{
  uint32_t key[MAX_RETURN_KEYS];
};


struct lddata
{
    int64_t V;
    int64_t e;
    uint32_t n_elements;
    uint32_t l;
    char map_init;
    map_int_t A;
};

uint32_t ldhash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    //printf("hh %d\n", key);
    ght_hash_key_t p_key;
    p_key.p_key = &new_key;
    p_key.i_size = sizeof(uint32_t);

    return ght_one_at_a_time_hash(&p_key);
}

struct bpf_map *ldsketch_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *ldsketchmap;
    uint64_t array_size;
    uint32_t elem_size;
   

    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size == 0 ||
        attr->value_size == 0) {
        errno = EINVAL;
        return NULL;
    }
    
    elem_size = attr->value_size*sizeof(struct lddata);
    /* allocate the mincountmap structure*/
    //mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    //printf("size %d \n", sizeof(struct return_keys));
    
    ldsketchmap = malloc((attr->max_entries) * elem_size + sizeof(struct bpf_array) + sizeof(struct return_keys));
    //printf("size %p \n", ldsketchmap->value );
    
    //memset(mincountmap, 0, attr->max_entries * elem_size + sizeof(*mincountmap));
    if (!ldsketchmap) {
        errno = ENOMEM;
        return NULL;
    }

    //printf("size %d %d %p %d\n", attr->max_entries , attr->value_size, mincountmap->value, ((mincountmap->value + attr->value_size*attr->max_entries*sizeof(int64_t))-mincountmap->value)/sizeof(int64_t));
    /* copy mandatory map attributes */
    ldsketchmap->map.map_type = attr->map_type;
    ldsketchmap->map.key_size = attr->key_size;
    ldsketchmap->map.value_size = elem_size;
    ldsketchmap->map.max_entries = attr->max_entries;

    ldsketchmap->elem_size = 1;

    return &ldsketchmap->map;

}

void ldsketch_map_free(struct bpf_map *map)
{
    struct bpf_array *array = (struct bpf_array*) container_of(map, struct bpf_array, map);
    free(array);
}




void *ldsketch_map_lookup_elem(struct bpf_map *map, void *key)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    
    uint32_t *mvret = (uint32_t*) array->value;
    *mvret = 0xFFFFFFFF;
    return mvret;
}

int ldsketch_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}



void update_bucket(struct lddata* bucket, const char *key, uint32_t value, uint32_t T){
   bucket->V += value;
   
   if(bucket->map_init == 0){
       map_init(&bucket->A);
       bucket->map_init = 1;
   }
 
   int *key_val = map_get(&bucket->A, key);
   if(key_val){
   	*key_val += value;
   }else if(bucket->n_elements < bucket->l){        
	map_set(&bucket->A, key, value);
   	bucket->n_elements++;   	
   } else{
       int k = bucket->V/T;
       if( ((k+1)*(k+2)-1) <= bucket->l){
           int e = value;
           const char *loca_key;
           
           map_iter_t iter = map_iter(&bucket->A);
	   
	   while ((loca_key = map_next(&bucket->A, &iter))) {
	     int *val = map_get(&bucket->A, loca_key);
	     e = *val < e ? *val : e;
	   }
           
           bucket->e = e;
           
           iter = map_iter(&bucket->A);
           while ((loca_key = map_next(&bucket->A, &iter))) {
	     int *val = map_get(&bucket->A, loca_key);
	     *val -= e;
	     if(*val < 0){
	       map_remove(&bucket->A, loca_key);
	       bucket->n_elements--; 
	     }
	   }
           if(value > e){
               map_set(&bucket->A, key, value);
               bucket->n_elements++;
           }
           
       }else{
          int new_l = ((k+1)*(k+2)-1);
          bucket->l = new_l;
          map_set(&bucket->A, key, value);
          bucket->n_elements++;
       }
   }
}


int ldsketch_map_update_elem(struct bpf_map *map, void *key, void *value,
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
    struct lddata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct lddata);
    uint32_t T = array->map.key_size;
    
    //printf("(%d)", (value));
    if(map_flags == BPF_CLEAN)
    {   printf("clean \n");
        
        for (index = 0; index < array->map.max_entries; index++ )
        {   
            ptr = &((struct lddata*) (array->value + sizeof(struct return_keys)))[num_elements*index];
            for (i = 0; i < num_elements; i++)
            {
                map_deinit(&ptr[i].A);            
            }
        }
        memset(array->value, 0, sizeof(struct return_keys) + array->map.max_entries*num_elements*sizeof(struct lddata));
        return 0;
    }
    char char_key[5];
    uint_to_char(*((uint32_t*) key), char_key);
    //printf("update %p\n", array->value);
    for (index = 0; index < array->map.max_entries; index++ ){
        ptr = &((struct lddata*) (array->value + sizeof(struct return_keys)))[num_elements*index];   
        hash_value = ldhash(*((uint32_t*) key), index, 41);
        hash_value = hash_value%(num_elements);
        //printf("lookup (Key %d) %d %p\n", *((int*) key), hash_value, ptr);
        update_bucket(&ptr[hash_value], char_key, *((int32_t*)value), T);
        
        uint32_t nkey = char_to_uint(char_key);    
	//printf("(%d %d)", nkey, *((uint32_t*) key));
    }
    
    return 0;
}

void* ldsketch_map_heavy_key_elem(struct bpf_map *map, int *num_return_keys, int phi){

   
    
    uint32_t i, index;
    uint32_t hash_value;
    struct lddata *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct lddata);
     
    map_int_t hashmap;
    map_init(&hashmap);
    
    char char_key[5];
        
    //printf("update %p\n", array->value);
    ptr = &((struct lddata*) (array->value + sizeof(struct return_keys)))[num_elements*0];  
    for(i = 0; i < num_elements; ++i){
    
        map_iter_t iter = map_iter(&ptr[i].A);
	const char *loca_key;
	while ((loca_key = map_next(&ptr[i].A, &iter))) {
	   int *val = map_get(&ptr[i].A, loca_key);
	   
	   if((*val + ptr[i].e) >= phi){
	       map_set(&hashmap, loca_key, 1);
	   }
	}
    }
    
    
    
    int num_keys = 0;
    map_iter_t iter = map_iter(&hashmap);
    const char *loca_key;
    while ((loca_key = map_next(&hashmap, &iter))) {
	int *val = map_get(&hashmap, loca_key);
        uint32_t key = char_to_uint(loca_key);
        bool is_heavy_key = true;
	for (index = 1; index < array->map.max_entries; index++ ){
            ptr = &((struct lddata*) (array->value + sizeof(struct return_keys)))[num_elements*index];    
         
            hash_value = ldhash(key, index, 41);
            hash_value = hash_value%(num_elements);
       
            int *val = map_get(&ptr[hash_value].A, loca_key);
            
            if((*val +  ptr[hash_value].e) < phi){
               is_heavy_key = false;
               break;
            }
        }
        if(is_heavy_key){
           ((uint32_t*) array->value)[num_keys] = key;
           num_keys++;
        }
        
        if(num_keys > MAX_RETURN_KEYS){
            break;
        }
    }
    
    map_deinit(&hashmap);
    
    *num_return_keys = num_keys;
    return (void*) array->value;

}

void* ldsketch_map_heavy_change_elem(struct bpf_map *map1, struct bpf_map *map2, int *num_return_keys, int phi){

    
    uint32_t i, index;
    uint32_t hash_value;
    struct lddata *ptr, *ptr2;
    struct bpf_array *array = container_of(map1, struct bpf_array, map);
    struct bpf_array *array2 = container_of(map2, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(struct lddata);
     
    map_int_t hashmap;
    map_init(&hashmap);
    
    char char_key[5];
        
    //printf("update %p\n", array->value);
    ptr = &((struct lddata*) (array->value + sizeof(struct return_keys)))[num_elements*0];
    ptr2 = &((struct lddata*) (array2->value + sizeof(struct return_keys)))[num_elements*0];   
    for(i = 0; i < num_elements; ++i){
    
        map_iter_t iter = map_iter(&ptr[i].A);
	const char *loca_key;
	while ((loca_key = map_next(&ptr[i].A, &iter))) {
	   int *val  = map_get(&ptr[i].A, loca_key);
	   if (ptr2[i].map_init == 0)
	      continue;
	   
	   int *val2 = map_get(&ptr2[i].A, loca_key);

	   if(!val2)		
		continue;
           int comp_value2 = *val2 + ptr2[i].e - *val;
           int comp_value  =  *val + ptr[i].e  - *val2;
	   if(comp_value2 > comp_value)
	       comp_value = comp_value2;
	   if(comp_value >= phi){
	           map_set(&hashmap, loca_key, abs(*val2 - *val));
	   }
	}
    }
    
    
    int num_keys = 0;
    map_iter_t iter = map_iter(&hashmap);
    const char *loca_key;
    while ((loca_key = map_next(&hashmap, &iter))) {
	int *val = map_get(&hashmap, loca_key);
        uint32_t key = char_to_uint(loca_key);
        bool is_heavy_key = true;
	for (index = 1; index < array->map.max_entries; index++ ){
            ptr   = &((struct lddata*) (array->value + sizeof(struct return_keys)))[num_elements*index];
            ptr2  = &((struct lddata*) (array2->value + sizeof(struct return_keys)))[num_elements*index];
         
            hash_value = ldhash(key, index, 41);
            hash_value = hash_value%(num_elements);
       
            int *val = map_get(&ptr[hash_value].A, loca_key);
            int *val2 = map_get(&ptr2[hash_value].A, loca_key);
            
            int comp_value2 = ptr2[i].e - ptr[i].e;
            
            if(val2)
               comp_value2 = *val2 + ptr2[i].e - *val;
            
            int comp_value  =  *val + ptr[i].e - *val2 ;
            
            if(comp_value2 > comp_value)
                comp_value = comp_value2;
            
            if(comp_value < phi){
               is_heavy_key = false;
               break;
            }
        }
        if(is_heavy_key){
           ((uint32_t*) array->value)[num_keys] = key;
           num_keys++;
        }
        
        if(num_keys > MAX_RETURN_KEYS){
            break;
        }
    }
    
    map_deinit(&hashmap);
    
    *num_return_keys = num_keys;
    return (void*) array->value;
    
    
    
}

int ldsketch_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}

int ldsketch_map_diff_elem(struct bpf_map *map_dest, struct bpf_map *map_src1, struct bpf_map *map_src2, uint32_t flag)
{
   
    return 0;
}
