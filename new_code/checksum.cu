#include "checksum.h"

struct iphdr {
  unsigned char  ihl:4,
    version:4;
  unsigned char  tos;
  unsigned short  tot_len;
  unsigned short  id;
  unsigned short  frag_off;
  unsigned char  ttl;
  unsigned char  protocol;
  unsigned short check;
  unsigned int  saddr;
  unsigned int  daddr;
};

typedef struct iphdr iphdr;

struct tcphdr {
  unsigned short  source;
  unsigned short  dest;
  unsigned int  seq;
  unsigned int  ack_seq;

  unsigned short  res1:4,
    doff:4,
    fin:1,
    syn:1,
    rst:1,
    psh:1,
    ack:1,
    urg:1,
    ece:1,
    cwr:1;
  unsigned short  window;
  unsigned short check;
  unsigned short  urg_ptr;
};

typedef struct tcphdr tcphdr;

__device__ bswap16(x) {
  return (x >> 8) | (x << 8)
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
__device__ unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&bswap16(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}


/* set ip checksum of a given ip header*/
__device__ void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

/* set tcp checksum: given IP header and tcp segment */
__device__ void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = bswap16(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += bswap16(IPPROTO_TCP);
    //the length
    sum += bswap16(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&bswap16(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}
