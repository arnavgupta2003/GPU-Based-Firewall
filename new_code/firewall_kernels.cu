#include <stdio.h>

extern "C" {
#include "firewall_kernels.h"
}
#include "rules.h"

struct iphdr {
    // unsigned char  ihl_version:4,
    // version:4;
    unsigned char ihl_version;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

typedef struct iphdr iphdr;

struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;

    unsigned short res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

typedef struct tcphdr tcphdr;

__device__ unsigned short bswap16(unsigned short x) {
    return (x >> 8) | (x << 8);
}

__device__ unsigned int bswap32(unsigned int x) {
    return ((x >> 24) & 0xff) |      // move byte 3 to byte 0
           ((x << 8) & 0xff0000) |   // move byte 1 to byte 2
           ((x >> 8) & 0xff00) |     // move byte 2 to byte 1
           ((x << 24) & 0xff000000); // byte 0 to byte 3
}

__device__ unsigned short compute_checksum(unsigned short* addr, unsigned int count) {
    unsigned long sum = 0;
    int idx=0;
    //ORG
    // while (count > 1) {
    //     sum += *addr++;
    //     count -= 2;
    // }

    //Mod 1
    while (count > 0) {
        sum += addr[idx];idx++;
        count -= 1;
        // printf("DEB: 0x%04x :val:0x%04x\n", sum,addr[idx-1]);
        if(sum>=0x10000){
            sum-=0x10000;
            sum+=0x1;
            // printf("Carry to sum: 0x%04x \n", sum);
        }
    }

    //Mod 2
    // while (count > 0) {
    //     sum += *addr++;
    //     count -= 1;
    //     //DEB
    //     printf("DEB: 0x%04x :val:0x%04x\n", sum,*addr);
    //     if(sum>=0x10000){
    //         sum-=0x10000;
    //         sum+=0x1;
    //         printf("Carry to sum: 0x%04x \n", sum);
    //     }
    // }

    //ORG
    if (count > 0) {
        sum += ((*addr) & 0xFF) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    return (unsigned short)sum;
}

/* set ip checksum of a given ip header*/
__device__ void compute_ip_checksum(struct iphdr* iphdrp, unsigned int junk) {
    //iphdrp->check = 0;
    junk = 0;
    iphdrp->check = compute_checksum((unsigned short*)iphdrp->check, ((iphdrp->ihl_version << 4) >> 4) << 2);
    //  iphdrp->check = compute_checksum((unsigned short*)iphdrp, ((junk << 4) >> 4) << 2);
    //iphdrp->check = compute_checksum((unsigned short*)iphdrp, ((junk << 4) >> 4) << 2);
    

}

/* set tcp checksum: given IP header and tcp segment */
__device__ void compute_tcp_checksum(char* pIph, unsigned short* ipPayload, unsigned int junk) {
    register unsigned long sum = 0;
    // printf("Is this misaligned? %d\n", pIph->tot_len);
    //unsigned short tcpLen = bswap16(pIph->tot_len) - (((pIph->ihl_version << 4) >> 4) << 2);
    unsigned short tcpLen = bswap16(0x6) - (((junk << 4) >> 4) << 2);
    // struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    // add the pseudo header
    // the source ip
    // sum += (pIph->saddr>>16)&0xFFFF;
    // sum += (pIph->saddr)&0xFFFF;
    //  sum += junk>>16&0xFFFF;
    //  sum += junk & 0xFFFF;
    // the dest ip
    // sum += (pIph->daddr>>16)&0xFFFF;
    // sum += (pIph->daddr)&0xFFFF;
    // protocol and reserved: 6
    sum += bswap16(0x6); // IPPROTO_TCP
    // the length
    sum += bswap16(tcpLen);

    // add the IP payload
    // initialize checksum to 0
    junk = 0;
    while (tcpLen > 1) {
        sum += *ipPayload++;
        tcpLen -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (tcpLen > 0) {
        // printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload) & bswap16(0xFF00));
    }
    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    // set computation result
    junk = (unsigned short)sum;
}

__device__ unsigned int fnv_hash_long(unsigned long l1) {
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

    return hash;
}

__device__ unsigned int fnv_hash_short(unsigned short l1) {
    unsigned int hash = 0x811c9dc5;

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)(l1 & 0xff);

    hash = hash * 0x01000193;
    hash = hash ^ (unsigned char)((l1 & 0xff00) >> 8);

    return hash;
}

__device__ unsigned int fnv_hash_gpu(unsigned long l1, unsigned long l2) {
    unsigned int hash = fnv_hash_long(l1);

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

__device__ unsigned int parse_int(char* array, int index) {
    unsigned char c1 = array[index];
    unsigned char c2 = array[index + 1];
    unsigned char c3 = array[index + 2];
    unsigned char c4 = array[index + 3];

    unsigned int val = c1;
    val              = val << 8;
    val              = val | c2;
    val              = val << 8;
    val              = val | c3;
    val              = val << 8;
    val              = val | c4;

    return val;
}

__device__ unsigned short parse_short(char* array, int index) {
    unsigned char c1 = array[index];
    unsigned char c2 = array[index + 1];

    unsigned short int val = c1;
    val                    = val << 8;
    val                    = val | c2;

    return val;
}

__global__ void process_pkt(char* input_buf,
                            char* output_buf,
                            int* len,
                            int num_pkts,
                            int buf_len,
                            unsigned long* rules,
                            int num_lines,
                            unsigned int* nat_table,
                            unsigned long* nat_set) {
    int tx = threadIdx.x;
    int pkt_start;
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned char protocol;
    unsigned char ip_header_len;

    bool drop = false;
    unsigned int hash;
    unsigned long l1;
    unsigned long l2;

    if (tx < num_pkts) {
        pkt_start = len[tx];

        ip_header_len = input_buf[pkt_start + 14];
        ip_header_len = ip_header_len << 4;
        ip_header_len = ip_header_len >> 4;
        ip_header_len = ip_header_len * 4;

        protocol = input_buf[pkt_start + 14 + 9];

        // For TCP
        if (protocol == 6) {

            src_addr = parse_int(input_buf, pkt_start + 14 + 12);

            dst_addr = parse_int(input_buf, pkt_start + 14 + 16);

            src_port = parse_short(input_buf, pkt_start + 14 + ip_header_len);

            dst_port = parse_short(input_buf, pkt_start + 14 + ip_header_len + 2);

            l1 = src_addr;
            l1 = l1 << 32 | dst_addr;
            l2 = src_port;
            l2 = l2 << 16 | dst_port;
            l2 = l2 << 8 | protocol;

            hash = fnv_hash_gpu(l1, l2) % 10000;

        }

        // For ICMP
        else if (protocol == 1) {
            src_addr = input_buf[pkt_start + 14 + 12];
            dst_addr = input_buf[pkt_start + 14 + 16];
            l1       = src_addr;
            l1       = l1 << 32 | dst_addr;
            l2       = protocol;
            // for (int i=0;i<25;i++)
            hash = fnv_hash_gpu(l1, l2) % 10000;
        }

        // For UDP
        else if (protocol == 17) {
            src_addr = input_buf[pkt_start + 14 + 12];
            src_port = input_buf[pkt_start + 14 + ip_header_len];
            dst_addr = input_buf[pkt_start + 14 + 16];
            dst_port = input_buf[pkt_start + 14 + ip_header_len + 2];

            l1 = src_addr;
            l1 = l1 << 32 | dst_addr;
            l2 = src_port;
            l2 = l2 << 16 | dst_port;
            l2 = l2 << 8 | protocol;

            // for (int i=0;i<25;i++)
            hash = fnv_hash_gpu(l1, l2) % 10000;
        }

        // For anything else
        else {
            for (int i = len[tx]; i < len[tx + 1]; i++) {
                output_buf[i] = input_buf[i];
            }
            return;
        }

        for (int j = 0; j < 10; j++) {
            int index = hash * 3 * 10 + j * 3;

            if ((rules[index] == l1) && (rules[index + 1] == l2)) {

                // Drop packet if it is found in the firewall rules and has id = 1
                if (rules[index + 2] == 1) {
                    drop = true;
                    break;
                }

                // Pass if id = 0 or anything else
                else
                    ;
            }
        }

        if (!drop) {

            // Dynamic NATing
            unsigned long l1   = src_addr;
            l1                 = l1 << 32 | src_port;
            unsigned int hash1 = fnv_hash_long(l1) % 10000;
            unsigned int hash2 = fnv_hash_short(dst_port) % 10000;

            if (((src_addr & 0xffffff00) == 0x0a000000) && ((dst_addr & 0xffffff00) != 0x0a000000)) {
                for (int i = 0; i < 10; i++) {
                    int index1 = hash1 * 10 + i;
                    if (nat_set[index1] == l1) {
                        // printf("hash1 is %u\n", hash1);
                        // printf("natset1 is %lu\n", nat_set[index1]);
                        break;
                    }
                    // printf("Starting NAT.\n");

                    if (nat_set[index1] == 0) {
                        nat_set[index1] = l1;
                        for (int j = 0; j < 10; j++) {
                            int index2 = hash2 * 2 * 10 + 2 * j;
                            if (nat_table[index2] == 0) {
                                nat_table[index2]     = dst_port;
                                nat_table[index2 + 1] = src_addr;
                                break;
                            }
                        }
                        break;
                    }
                }

                input_buf[pkt_start+14+12] = 0x14;
                input_buf[pkt_start+14+13] = 0x00;
                input_buf[pkt_start+14+14] = 0x00;
                input_buf[pkt_start+14+15] = 0x01;
                // printf("Ending NAT.\n");

                compute_tcp_checksum(
                  &input_buf[pkt_start + 14], (unsigned short*)input_buf[pkt_start + ip_header_len], num_lines);

                compute_ip_checksum((struct iphdr*)&input_buf[pkt_start + 14], num_lines);

            }

            else if (dst_addr == 0x14000001) {
                unsigned int nat_ip;
                unsigned int hash2 = fnv_hash_short(dst_port) % 10000;
                for (int i = 0; i < 10; i++) {
                    int index = hash2 * 2 * 10 + 2 * i;
                    if (nat_table[index] == dst_port) {
                        nat_ip = nat_table[index + 1];
                    }
                }

                input_buf[pkt_start+14+12] = nat_ip >> 24;
                input_buf[pkt_start+14+13] = (nat_ip << 8) >> 24;
                input_buf[pkt_start+14+14] = (nat_ip << 16) >> 24;
                input_buf[pkt_start+14+15] = (nat_ip << 24) >> 24;

                compute_tcp_checksum(
                  &input_buf[pkt_start + 14], (unsigned short*)input_buf[pkt_start + ip_header_len], num_lines);

                compute_ip_checksum((struct iphdr*)&input_buf[pkt_start + 14], num_lines);
            }

            // Intranet packet
            else
                ;

            // printf("Packet passed. Copying...\n");
            for (int i = len[tx]; i < len[tx + 1]; i++) {
                output_buf[i] = input_buf[i];
            }
        }
    }
}

void run_firewall(char* input_buf,
                  char* output_buf,
                  int* len,
                  int num_pkts,
                  int buf_len,
                  unsigned long* rules,
                  int num_lines,
                  unsigned int* nat_table,
                  unsigned long* nat_set) {
    // Allocate device memory
    char* d_input_buf;
    char* d_output_buf;
    int* d_len;

    cudaMalloc((void**)&d_input_buf, buf_len * sizeof(char));
    cudaMalloc((void**)&d_output_buf, buf_len * sizeof(char));
    cudaMalloc((void**)&d_len, (num_pkts + 1) * sizeof(int));

    // Copy input buffer and len array to device memory
    cudaMemcpy(d_input_buf, input_buf, buf_len * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_len, len, (num_pkts + 1) * sizeof(int), cudaMemcpyHostToDevice);

    // Launch process_pkts kernel
    // Note: Only launching 1 block with 1024 threads at the moment
    // printf("You broke something\n");
    process_pkt<<<1, 1024>>>(d_input_buf, d_output_buf, d_len, num_pkts, buf_len, rules, num_lines, nat_table, nat_set);
    cudaDeviceSynchronize();

    // Copy output buffer to host memory
    cudaMemcpy(output_buf, d_output_buf, buf_len * sizeof(char), cudaMemcpyDeviceToHost);

    // Free device memory
    cudaFree(d_input_buf);
    cudaFree(d_output_buf);
    cudaFree(d_len);
}
