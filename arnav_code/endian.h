//this header file is for network functions that can't be accessed by the GPU directly, so these functions use primitive data types so that they can work on the GPU.
#ifndef ENDIAN_H
#define ENDIAN_H

// unsigned short inet_chksum(void *data, int len);
// unsigned short inet_chksum_pbuf(struct pbuf *p);
// unsigned short inet_chksum_pseudo(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest, unsigned char proto, unsigned short proto_len);

#if BYTE_ORDER == BIG_ENDIAN

#define NEWHTONS(n) (n)
#define NEWNTOHS(n) (n)
#define NEWHTONL(n) (n)
#define NEWNTOHL(n) (n)

#else

#define NEWHTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NEWNTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define NEWHTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NEWNTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#endif


unsigned short newhtons(unsigned short n);
unsigned short newntohs(unsigned short n);
unsigned long newhtonl(unsigned long n);
unsigned long newntohl(unsigned long n);

#define newhtons(n) NEWHTONS(n)
#define newntohs(n) NEWNTOHS(n)

#define newhtonl(n) NEWHTONL(n)
#define newntohl(n) NEWNTOHL(n)


#endif
