#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern "C" {
#include "rules.h"
}

unsigned int fnv_hash(unsigned long l1, unsigned long l2) {
    unsigned int hash = 0x811c9dc5;

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)(l1 & 0xff);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff00) >> 8);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff0000) >> 16);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff000000) >> 24);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff00000000) >> 32);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff0000000000) >> 40);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff000000000000) >> 48);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff00000000000000) >> 56);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)(l2 & 0xff);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l2 & 0xff00) >> 8);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l2 & 0xff0000) >> 16);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l2 & 0xff000000) >> 24);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l2 & 0xff00000000) >> 32);

    return hash;
}


const char *getfield(char* line, int num) {
    const char *tok;
    for (tok = strtok(line, ",");
        tok && *tok;
        tok = strtok(NULL, ",")) {
        if (!--num)
            return tok;
    }
    return NULL;
}

int assign_protocol_number(const char *str) {
    if(strcmp(str, "icmp") == 0) {
        return 1;
    }
    else if(strcmp(str, "tcp") == 0) {
        return 6;
    }
    else if(strcmp(str, "udp") == 0) {
        return 17;
    }
    else {
        return -1;
    }
}

int load_rules(char *filename, unsigned long **d_ruleset) { 
    // Load rules
    FILE *ruleset = fopen(filename, "r");
    char line[64];
    int num_lines, k = 0;

    while (EOF != (fscanf(ruleset, "%*[^\n]"), fscanf(ruleset,"%*c")))
        ++num_lines;

    unsigned long *rules = (unsigned long *)malloc(3 * 10 * num_lines * (sizeof(unsigned long)));

    for(int i=0;i<10*num_lines;i++) {
        rules[(i+1) * 3 - 1] = 255;
    }

    fclose(ruleset);
    ruleset = fopen(filename, "r");


    // int *collisions = (int *)malloc(10000*sizeof(int));
    //     for(int i=0;i<10000;i++) {
    //     collisions[i] = 0;
    // }

    while (fgets(line, 64, ruleset)) {
        char* tmp1 = strdup(line);
        char* tmp2 = strdup(line);
        char* tmp3 = strdup(line);
        char* tmp4 = strdup(line);
        char* tmp5 = strdup(line);
        char* tmp6 = strdup(line);

        // LITTLE ENDIAN

        unsigned int src_addr = ntohl(inet_addr(getfield(tmp1, 1)));
        unsigned int dst_addr = ntohl(inet_addr(getfield(tmp2, 2)));
        unsigned short int src_port = atoi(getfield(tmp3, 3));
        unsigned short int dst_port = atoi(getfield(tmp4, 4));
        unsigned char protocol = assign_protocol_number(getfield(tmp5, 5));
        unsigned char action = atoi(getfield(tmp6, 6));


        unsigned long l1 = src_addr;
        l1 = l1 << 32 | dst_addr;
        unsigned long l2 = src_port;
        l2 = l2 << 16 | dst_port;
        l2 = l2 << 8 | protocol;

        // REMOVE LATER
        // l2 = l1;

        // printf("Rule: %u %u %hu %hu %d %d %lu %lu\n", src_addr, dst_addr, src_port, dst_port, protocol, action, l1, l2);
        
        unsigned int hash = fnv_hash(l1, l2) % 10000;
        // printf("hash: %u\n", hash);
        // printf("src: %u, dst: %u\n, src_port: %hu, dst_port: %hu, protocol: %d", src_addr, dst_addr, src_port, dst_port, protocol);
        // printf("l1: %lu, l2: %lu\n", l1, l2);        
        
        // collisions[hash]++;


        // printf("Rule: %u %u %hu %hu %d %d %lu %lu %u\n", src_addr, dst_addr, src_port, dst_port, protocol, action, l1, l2, hash);

        for(int j=0;j<10;j++) {
            int index = hash * 3 * 10 + j * 3;
            if (rules[index+2] == 255) {
                rules[index] = l1;
                rules[index+1] = l2;
                rules[index+2] = action;
                break;
            } 
        }

        free(tmp1);
        free(tmp2);
        free(tmp3);
        free(tmp4);
        free(tmp5);
        free(tmp6);
        k++;

        // for(int i=0;i<10000;i++) {
        //     for(int j=0;j<10;j++) {
        //         printf("i:%d, j:%d, l1:%lu, l2:%lu, l3:%lu\n", i, j, rules[i*30+j*3], rules[i*30+j*3+1], rules[i*30+j*3+2]);
        //     }
        // }   

        // exit(0);
    }

    unsigned long *d_rules;
    cudaMalloc((void**)&d_rules, 3 * 10 * num_lines * sizeof(unsigned long));
    cudaMemcpy(d_rules, rules, 3 * 10 * num_lines * sizeof(unsigned long), cudaMemcpyHostToDevice);

    *d_ruleset = d_rules;

    // int max = -1;
    // for(int i=0;i<10000;i++) {
    //     if (collisions[i]>max) {
    //         max = collisions[i];
    //     }
    // }

    // printf("collisions: %d\n", max);

    // free(collisions);


    // for(int i=0;i<10000;i++) {
    //     for(int j=0;j<10;j++) {
    //         printf("i:%d, j:%d, l1:%lu, l2:%lu, l3:%lu\n", i, j, rules[i*30+j*3], rules[i*30+j*3+1], rules[i*30+j*3+2]);
    //     }
    // }

    free(rules); 

    return num_lines;
}

int free_rules(unsigned long *d_rules) {
    cudaFree(d_rules);
    return 0;
}
