#ifndef RULES_H
#define RULES_H

struct rule {
    unsigned char protocol;
    // unsigned char action;
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned int src_addr;
    unsigned int dst_addr;
};

int load_rules(char *filename, unsigned long **d_ruleset);
int free_rules(unsigned long *d_rules);

#endif