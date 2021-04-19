#ifndef __EBPF_UTILS_H
#define __EBPF_UTILS_H
#include<stdio.h>
#include <stdint.h>

void saveLog(const char* log_file, uint64_t value);
void saveLog2(const char* log_file, uint64_t value1, uint64_t value2);



#endif
