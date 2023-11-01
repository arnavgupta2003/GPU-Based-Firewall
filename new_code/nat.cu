#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnetmap.h>

extern "C" {
#include "nat.h"
}

int allocate_nat_table(unsigned int **d_nat) {
  unsigned int *d_nat_tmp;
  cudaMalloc((void **)&d_nat_tmp, 2 * 10 * 10000 * sizeof(unsigned int));
  cudaMemset(d_nat_tmp, 0, 2 * 10 * 10000 * sizeof(unsigned int));

  *d_nat = d_nat_tmp;

  return 0;
}

int allocate_nat_set(unsigned long **d_nat) {
  unsigned long *d_nat_tmp;
  cudaMalloc((void **)&d_nat_tmp, 10 * 10000 * sizeof(unsigned long));
  cudaMemset(d_nat_tmp, 0, 10 * 10000 * sizeof(unsigned long));

  *d_nat = d_nat_tmp;

  return 0;
}

int free_nat(unsigned int *d_nat_table, unsigned long *d_nat_set) {
  cudaFree(d_nat_table);
  cudaFree(d_nat_set);
  return 0;
}

int allocate_buf(char **buf) {
  char* buf_temp;

  int a =cudaMallocManaged((char **)&buf_temp, 1518 * 1024  * sizeof(char));
  *buf=buf_temp;

  return 0;
}

int free_buf(char *buf){

  cudaFree(buf);
  return 0;
}