#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#define DEBUG_ENV 1

#include "karymap.h"
#include "libghthash/ght_hash_table.h"


//
// HEAP
//

void kary_satisfy_heap(int64_t a[], int i, int heap_size) {
  int l, r, largest, temp;
  l = 2 * i;
  r = 2 * i + 1;
  if (l <= heap_size && a[l] > a[i]) {
    largest = l;
  } else {
    largest = i;
  }
  if (r <= heap_size && a[r] > a[largest]) {
    largest = r;
  }
  if (largest != i) {
    temp = a[i];
    a[i] = a[largest];
    a[largest] = temp;
    kary_satisfy_heap(a, largest, heap_size);
  }
}

void kary_build_heap(int64_t a[], int n) {
  int i, heap_size;
  heap_size = n - 1;
  for (i = (n / 2); i >= 0; i--) {
    kary_satisfy_heap(a, i, heap_size);
  }
}

void kary_heap_sort(int64_t a[], int n) {
  kary_build_heap(a, n);
  int64_t heap_size, i, temp;
  heap_size = n - 1;
  for (i = heap_size; i >= 0; i--) {
    temp = a[0];
    a[0] = a[heap_size];
    a[heap_size] = temp;
    heap_size--;
    kary_satisfy_heap(a, 0, heap_size);
  }
}


//
// END HEAP
//


uint32_t karyhash(uint32_t key, uint32_t param1, uint32_t param2){
    //printf("hh %d %d %d\n", key, param1, key*7 + param1*13 + 31*param2);
    
    uint32_t new_key = (key+param1)*7 + param1*13 + 31*param2;
    //printf("hh %d\n", key);
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

    elem_size = attr->value_size*sizeof(int64_t);
    /* allocate the mincountmap structure*/
    //mincountmap = calloc(attr->max_entries * elem_size, sizeof(*mincountmap));
    
    mincountmap = malloc((attr->max_entries) * elem_size + sizeof(struct bpf_array) + sizeof(uint32_t));
    //memset(mincountmap, 0, attr->max_entries * elem_size + sizeof(*mincountmap));
    if (!mincountmap) {
        errno = ENOMEM;
        return NULL;
    }

#ifdef DEBUG_ENV
   saveLog("/tmp/KARY", (attr->max_entries) * elem_size );
#endif


    //printf("size %d %d %p %d\n", attr->max_entries , attr->value_size, mincountmap->value, ((mincountmap->value + attr->value_size*attr->max_entries*sizeof(int64_t))-mincountmap->value)/sizeof(int64_t));
    /* copy mandatory map attributes */
    mincountmap->map.map_type = attr->map_type;
    mincountmap->map.key_size = sizeof(int64_t);
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
    uint32_t index, hash_value, i, j;
    


    int64_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(int64_t);

    uint32_t* ret = (uint32_t*) array->value;//calloc(1, sizeof(int64_t));
    *ret = 0xFFFFFFFF;

    uint  num_ret_values = array->map.max_entries*array->elem_size;
    int64_t* return_vect = calloc(num_ret_values, sizeof(int64_t));
     
    j = 0;
    for (index = 0; index < array->map.max_entries; index++ ){
    	ptr = &((int64_t*) array->value + sizeof(uint32_t))[num_elements*index];
    	for (i = 0; i < array->elem_size; i++)
        {
    	    hash_value = karyhash(*((uint32_t*) key), index, i);    	    
    	    hash_value = hash_value%(num_elements);
            //printf("hash %d key %d \n", hash_value, *((uint32_t*) key));
    	    return_vect[j++] = ptr[hash_value];
            //printf("%d %d \n", *((int*) key), ptr[hash_value]);
            //printf("lookup (Key %d) %d %d %d (%d)\n", *((int*) key), index, i, num_elements , hash_value);
        }
        //printf("\n");
    }
    
    kary_heap_sort(return_vect, num_ret_values);
    *ret = return_vect[(int64_t)num_ret_values/2];
    /*for (j = 0; j < num_ret_values; j++){
        printf("%d ", return_vect[j]);
    }
    printf("\n");*/

    free(return_vect);    



    //printf("found %d\n", *ret);
    return ret;
}

int kary_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    errno = EINVAL;
    return -1;
}

//! Byte swap unsigned int
uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
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
    int64_t *ptr;
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint num_elements = array->map.value_size/sizeof(int64_t);
    
    
    //printf("(%d)", (value));
    if(map_flags == BPF_CLEAN)
    {   printf("clean \n");
        memset(array->value, 0, array->map.max_entries*num_elements*sizeof(int64_t) + sizeof(uint32_t));
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
        ptr = &((int64_t*) array->value + sizeof(uint32_t))[num_elements*index];
        for (i = 0; i < array->elem_size; i++)
        {
           
            hash_value = karyhash(*((uint32_t*) key), index, i);
            hash_value = hash_value%(num_elements);
            //printf("lookup (Key %d) %d\n", *((int*) key), hash_value);
            ptr[hash_value] += *((int64_t*)value);
            
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
    int64_t *ptr_dst, *ptr_src1, *ptr_src2;
    uint num_elements = array_dst->map.value_size/sizeof(int64_t);

    //printf("%d %d \n", map_src1, num_elements);
    for (index = 0; index < array_src1->map.max_entries; index++ )
    {   
        ptr_dst  = &((int64_t*) array_dst->value)[num_elements*index]; //(int64_t*) array_dst->value  + array_dst->map.value_size*index;
        ptr_src1 = &((int64_t*) array_src1->value)[num_elements*index]; //int64_t*) array_src1->value + array_src1->map.value_size*index;
        ptr_src2 = &((int64_t*) array_src2->value)[num_elements*index];  //(int64_t*) array_src2->value + array_src2->map.value_size*index;

          
        //printf("diff %d\n", index);
        for (i = 0; i < num_elements; i++)
        {
            ptr_dst[i] = abs(ptr_src1[i] - ptr_src2[i]);
            //if( ptr_dst[i] > 100000 || ptr_dst[i] < -100000)
                //printf("%ld ",  ptr_dst[i]);          
        }
    }
    //printf("\n\n\n\n\n\n\n\n");

    return 0;
}
