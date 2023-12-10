#include <iostream>
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
extern "C" {
#include "firewall_kernels.h"
}
#include "rules.h"
#include <time.h>
struct timespec time1;

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

__device__ uint32_t device_ntohl(uint32_t x) {
    return ((x & 0xFF) << 24) | (((x >> 8) & 0xFF) << 16) | (((x >> 16) & 0xFF) << 8) | ((x >> 24) & 0xFF);
}

__device__ unsigned short compute_checksum(unsigned short* addr, unsigned int count) {
    unsigned long sum = 0;
    int idx=0;


    //Mod 3
    while (count > 0) {
        // unsigned int temp = addr[idx]*100;
        // idx++;
        // temp+=addr[idx];idx++;

        // sum += addr[idx];idx++;
        sum+=*addr++;
      
        count -= 1;
        // printf("DEB: 0x%04x :val:0x%04x \n", sum,addr[idx-1]);
        if(sum>=0x10000){
            sum-=0x10000;
            sum+=0x1;
            // printf("Carry to sum: 0x%04x \n", sum);
        }
    }


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

    iphdrp->check=0x0000;
    // iphdrp->check = compute_checksum((unsigned short*)iphdrp->check, ((iphdrp->ihl_version << 4) >> 4) << 2);
    iphdrp->check = compute_checksum((unsigned short *)iphdrp,10);

    

}
__device__ unsigned short swap_bytes(unsigned short val) {
    return (val << 8) | (val >> 8);
}




__device__ void compute_tcp_checksum(struct tcphdr* tcphdrp, unsigned short* ipPayload, struct iphdr* iphdrp) {
    


    // Mod 2
    register uint32_t sum = 0;


    uint32_t tot_l =-1;

    for(int i=0;i<=5;i++){
        
        if(i==1) {
            sum+=(*ipPayload++);
            // *ipPayload++;
            tot_l=sum>>8;
            // printf("TOT len 0x%04x \n",tot_l);
            sum=0;
        }
        else{
            *ipPayload++;
        }
        // printf("DEB Skip SUM: 0x%04x | nxt val 0x%04x :\n", sum,*ipPayload);
    }

    // unsigned short tL = ntohs(tot_l) - (0x45<<2);
    
    // Add the pseudo header
    // printf("DEB SUM chksm: 0x%04x :\n", sum);
    sum+= (*ipPayload++) ;
    sum+= (*ipPayload++);//src IP
    // printf("DEB SUM chksm: 0x%04x :\n", sum);
    sum+= (*ipPayload++) ;
    sum+= (*ipPayload++);//dest IP
    // printf("DEB SUM chksm: 0x%04x :\n", sum);

    sum += 0x0600;
    // printf("DEB SUM chksm: 0x%04x : --Added Ps\n", sum);
    
    int tcpLen = (int)tot_l - 20;
    // printf("TCP LEN: %d  hex 0x%04x\n",tcpLen,tcpLen<<8);
    sum+=tcpLen<<8;
    // Add the IP payload
    // printf("Loop  st:10 end:%d\n",(tcpLen+1)/2 +9);
    for (int i = 10; i <= (tcpLen+1)/2 +9; i++) {//issue
        if(i!=18) {
            sum += *ipPayload++;
            // printf("DEB SUM chksm: 0x%04x | nxt val 0x%04x :\n", sum,*ipPayload);
        }else{
            // printf("SLIP :%d\n",i);
            *ipPayload++;
        }
    }

    // If any bytes left, pad the bytes and add
    // if (ipPayloadLen % 2 != 0) {
    //     sum += ((unsigned short)pIph[junk] << 8);
    // }

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;

    // Set computation result
    tcphdrp->check = (unsigned short)sum;

    int junk =  (unsigned short)sum;

    // printf("DEB chksm FINAL: 0x%04x :\n", junk);


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

            // src_addr = parse_int(input_buf, pkt_start + 14 + 12);

            // dst_addr = parse_int(input_buf, pkt_start + 14 + 16);

            src_port = parse_short(input_buf, pkt_start + 14 + ip_header_len);

            dst_port = parse_short(input_buf, pkt_start + 14 + ip_header_len + 2);

            //inet_addr convert ntohl done
            int pkt_inaddr_src = device_ntohl(((uint32_t)input_buf[pkt_start + 14 + 15] << 24) | ((uint32_t)input_buf[pkt_start + 14 + 14] << 16) |
            ((uint32_t)input_buf[pkt_start + 14 + 13] << 8) |(uint32_t)input_buf[pkt_start + 14 + 12]);

            int pkt_inaddr_dst = device_ntohl(((uint32_t)input_buf[pkt_start + 14 + 19] << 24) | ((uint32_t)input_buf[pkt_start + 14 + 18] << 16) |
            ((uint32_t)input_buf[pkt_start + 14 + 17] << 8) |(uint32_t)input_buf[pkt_start + 14 + 16]);


            l1 = pkt_inaddr_src;
            l1 = l1 << 32 | pkt_inaddr_dst;
            l2 = src_port;
            l2 = l2 << 16 | dst_port;
            l2 = l2 << 8 | protocol;

            hash = fnv_hash_gpu(l1, l2) % 10000;

        }

        // For ICMP
        else if (protocol == 1) {
            //inet_addr convert ntohl done
            int pkt_inaddr_src = device_ntohl(((uint32_t)input_buf[pkt_start + 14 + 15] << 24) | ((uint32_t)input_buf[pkt_start + 14 + 14] << 16) |
            ((uint32_t)input_buf[pkt_start + 14 + 13] << 8) |(uint32_t)input_buf[pkt_start + 14 + 12]);

            int pkt_inaddr_dst = device_ntohl(((uint32_t)input_buf[pkt_start + 14 + 19] << 24) | ((uint32_t)input_buf[pkt_start + 14 + 18] << 16) |
            ((uint32_t)input_buf[pkt_start + 14 + 17] << 8) |(uint32_t)input_buf[pkt_start + 14 + 16]);

            src_addr = pkt_inaddr_src;
            dst_addr = pkt_inaddr_dst;
            l1       = src_addr;
            l1       = l1 << 32 | dst_addr;
            l2       = protocol;

            hash = fnv_hash_gpu(l1, l2) % 10000;
            
            // printf("TEMP src (%d)\n  dst (%d)\n",(pkt_inaddr_src),pkt_inaddr_dst);
            // printf("PKT STATS: %d , %d ,%d , %d ,%d -- ",src_addr,dst_addr,src_port,dst_port,hash);
            // printf("PKT> src: %u, dst: %u, src_port: %hu, dst_port: %hu, protocol: %d , Hash %d , l1 %lu, l2 %lu ,", src_addr, dst_addr, src_port, dst_port, protocol,hash,l1,l2);
        
        }

        // For UDP
        else if (protocol == 17) {
            //inet_addr convert ntohl done
            int pkt_inaddr_src = device_ntohl(((uint32_t)input_buf[pkt_start + 14 + 15] << 24) | ((uint32_t)input_buf[pkt_start + 14 + 14] << 16) |
            ((uint32_t)input_buf[pkt_start + 14 + 13] << 8) |(uint32_t)input_buf[pkt_start + 14 + 12]);

            int pkt_inaddr_dst = device_ntohl(((uint32_t)input_buf[pkt_start + 14 + 19] << 24) | ((uint32_t)input_buf[pkt_start + 14 + 18] << 16) |
            ((uint32_t)input_buf[pkt_start + 14 + 17] << 8) |(uint32_t)input_buf[pkt_start + 14 + 16]);

            src_addr = pkt_inaddr_src;
            src_port = input_buf[pkt_start + 14 + ip_header_len];
            dst_addr = pkt_inaddr_dst;
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
            // printf(" --- idx :%d  ",index);

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
        // printf("\n");
        if (!drop) {

            // Dynamic NATing
            unsigned long l1   = src_addr;
            l1                 = l1 << 32 | src_port;
            unsigned int hash1 = fnv_hash_long(l1) % 10000;
            unsigned int hash2 = fnv_hash_short(dst_port) % 10000;
            //DEB:
            // printf("Before NAT IF: %u %u port: %u %u \n",src_addr,dst_addr,src_port,dst_port);
            //Close DEB

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

                            // //DEB:
                            
                            // printf("Before DEB: %u %lu \n",nat_table[index2],nat_table[index2+1]);
                            
                            // //Close DEB
                            if (nat_table[index2] == 0) {
                                nat_table[index2]     = dst_port;
                                nat_table[index2 + 1] = src_addr;

                             
                                
                                break;
                            }

                           
                        }
                        break;
                    }

                    
                }

                // input_buf[pkt_start+14+12] = 0x14;
                // input_buf[pkt_start+14+13] = 0x00;
                // input_buf[pkt_start+14+14] = 0x00;
                // input_buf[pkt_start+14+15] = 0x01;
                // printf("Ending NAT. deb: %c %c %c %c \n",input_buf[pkt_start+14+12],input_buf[pkt_start+14+13],
                //     input_buf[pkt_start+14+14],input_buf[pkt_start+14+15]);

                //DEB: printing NAT
                // for(int i=0;i<sizeof(nat_table);i++){
                //     printf("NAT[%d] %lu \n",i,nat_table[i]);
                // }

                // printf("Ending NAT\n");
                //ENDIng DEB

                //DEB:printing input_buf
                // for (int i = pkt_start; i < pkt_start+14+18; ++i)
                // {
                    // printf("0x%04x \n",input_buf[i]);
                // }
                //Ending deb
                
                // compute_tcp_checksum(
                //   (struct tcphdr*)&input_buf[pkt_start + 34], (unsigned short*)&input_buf[pkt_start +14], (struct iphdr*)&input_buf[pkt_start + 14]);

                // compute_ip_checksum((struct iphdr*)&input_buf[pkt_start + 14], num_lines);


               
            }

            else if (dst_addr == 0xA000001) {//dest_add = 10.0.0.1
                unsigned int nat_ip;
                unsigned int hash2 = fnv_hash_short(dst_port) % 10000;
                for (int i = 0; i < 10; i++) {
                    int index = hash2 * 2 * 10 + 2 * i;
                    if (nat_table[index] == dst_port) {
                        nat_ip = nat_table[index + 1];
                    }
                }

                // input_buf[pkt_start+14+12] = nat_ip >> 24;
                // input_buf[pkt_start+14+13] = (nat_ip << 8) >> 24;
                // input_buf[pkt_start+14+14] = (nat_ip << 16) >> 24;
                // input_buf[pkt_start+14+15] = (nat_ip << 24) >> 24;

                
                // compute_tcp_checksum(
                //   (struct tcphdr*)&input_buf[pkt_start + 34], (unsigned short*)&input_buf[pkt_start +14], (struct iphdr*)&input_buf[pkt_start + 14]);

                // compute_ip_checksum((struct iphdr*)&input_buf[pkt_start + 14], num_lines);

               
            }

            // Intranet packet
           
                

            // printf("Packet passed. Copying...\n");
            for (int i = len[tx]; i < len[tx + 1]; i++) {
                output_buf[i] = input_buf[i];
            }
        }else{
            // printf("DROP PJKT");
            for (int i = len[tx]; i < len[tx + 1]; i++) {
                input_buf[i] = 255;//drop pkt
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
    int* d_len;

    cudaMalloc((void**)&d_len, (num_pkts + 1) * sizeof(int));
    cudaMemcpy(d_len, len, (num_pkts + 1) * sizeof(int), cudaMemcpyHostToDevice);

    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("Just Before GPU COPY: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);

    // Launch process_pkts kernel with appropriate block and thread configuration
    int threads_per_block = 64;  // You can adjust this as needed
    int num_blocks = (num_pkts + threads_per_block - 1) / threads_per_block;
    process_pkt<<<num_blocks, threads_per_block>>>(input_buf, output_buf, d_len, num_pkts, buf_len,rules, num_lines, nat_table, nat_set);
    // d_input_buf, d_output_buf, d_len, num_pkts, buf_len, rules, num_lines, nat_table, nat_set
    cudaDeviceSynchronize();
    cudaFree(d_len);

    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("Just After GPU COPY: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);

}



