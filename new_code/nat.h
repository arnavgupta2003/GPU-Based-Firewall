#ifndef NAT_H
#define NAT_H

int allocate_nat_table(unsigned int**);
int allocate_nat_set(unsigned long**);
int free_nat(unsigned int*, unsigned long*);
int allocate_buf(char **buf);
int free_buf(char *buf);

#endif