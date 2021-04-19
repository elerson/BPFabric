#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

void saveLog(const char* log_file, uint64_t value){
   FILE *fptr = fopen(log_file, "w");
   fprintf(fptr,"%ld",value);
   fclose(fptr);
   
   //chmod(log_file, 0777);
}

void saveLog2(const char* log_file, uint64_t value1, uint64_t value2){
   FILE *fptr = fopen(log_file, "w");
   fprintf(fptr,"%ld %ld",value1, value2);
   fclose(fptr);
   
   //chmod(log_file, 0777);
}
