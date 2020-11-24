#include "b.h"
#define SIZE_ETHERNET 14 //size of an ethernet frame

#define isAscii(X) ((X) >= 0 && (X) <= 127)
#define isDigit(X) ((X) >= '0' && (X) <= '9')
#define isLower(X) ((X) >= 'a' && (X) <= 'z')

#define UC(c) ((unsigned char)c)

extern "C" char* kernel_wrapper(char *buf); //So that this function can be called from other 'C' file.

// __device__ int isDigit (char c) {
//   return (c>='0') && (c<='9');
// }

__device__ char isXdigit(unsigned char c)
{
    if ((c >= UC('0') && c <= UC('9')) ||
        (c >= UC('a') && c <= UC('f')) ||
        (c >= UC('A') && c <= UC('F')))
        return 1;
    return 0;
}

__device__ char isSpace(unsigned char c)
{
    if (c == UC(' ') ||
        c == UC('\f') ||
        c == UC('\n') ||
        c == UC('\r') ||
        c == UC('\t') ||
        c == UC('\v'))
        return 1;
    return 0;
}

__device__ int aux_inet_aton(const char *cp, struct in_addr *addr)
{
    u_long val, base, n;
    char c;
    u_long parts[4], *pp = parts;

    for (;;)
    {
        /*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
        val = 0;
        base = 10;
        if (*cp == '0')
        {
            if (*++cp == 'x' || *cp == 'X')
                base = 16, cp++;
            else
                base = 8;
        }
        while ((c = *cp) != '\0')
        {
            if (isAscii(c) && isDigit(c))
            {
                val = (val * base) + (c - '0');
                cp++;
                continue;
            }
            if (base == 16 && isAscii(c) && isXdigit(c))
            {
                val = (val << 4) +
                      (c + 10 - (isLower(c) ? 'a' : 'A'));
                cp++;
                continue;
            }
            break;
        }
        if (*cp == '.')
        {
            /*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
            if (pp >= parts + 3 || val > 0xff)
                return (0);
            *pp++ = val, cp++;
        }
        else
            break;
    }
    /*
	 * Check for trailing characters.
	 */
    if (*cp && (!isAscii(*cp) || !isSpace(*cp)))
        return (0);
    /*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
    n = pp - parts + 1;
    switch (n)
    {

    case 1: /* a -- 32 bits */
        break;

    case 2: /* a.b -- 8.24 bits */
        if (val > 0xffffff)
            return (0);
        val |= parts[0] << 24;
        break;

    case 3: /* a.b.c -- 8.8.16 bits */
        if (val > 0xffff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;

    case 4: /* a.b.c.d -- 8.8.8.8 bits */
        if (val > 0xff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    }
    if (addr)
        addr->s_addr = newhtonl(val);
    return (1);
}

__device__ in_addr_t getInetAddr(const char *cp)
{
    struct in_addr val;
    if (aux_inet_aton(cp, &val))
        return (val.s_addr);
    return (INADDR_NONE);
}

__global__ void nat(char *buf)
{

  struct iphdr *ip_info;
  ip_info = (struct iphdr *)(buf + SIZE_ETHERNET);
// __syncthreads();
  __u32 *newSrc;
  newSrc = (__u32 *)malloc(sizeof(__u32));
  // *newSrc = getInetAddr("192.168.137.1");
  ip_info->daddr = *newSrc; //Changing THE Source ADDRESS INSIDE KERNEL

  /*

```````````WRITE ANY TESTING CODE IN THIS SECTION PLEASE```````````
// printf("\nsource address before checksum %x\n",newntohl(ip_info->saddr));

*/

  //CHECKSUM CALCULATION STARTS -------------------------------------------------------------------------------

  // compute_ip_checksum(ip_info);

  ip_info->check = 0;
  // printf("\nIN CUDA, checksum before calculation %x \n",ip_info->check);
  unsigned short *addr = (unsigned short *)ip_info;
  unsigned int count = ip_info->ihl << 2;
  register unsigned long sum = 0;
  while (count > 1)
  {
      sum += *addr++;
      count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if (count > 0)
  {
      sum += ((*addr) & newhtons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum >> 16)
  {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  ip_info->check = ((unsigned short)sum);

  //For tcp checksum calculation, applicable for TCP packets ~~~~~~~~~~~~~~~~~~~~~~~~~~
  struct tcphdr *tcpHeader;
  tcpHeader = (struct tcphdr *)(buf + SIZE_ETHERNET + (ip_info->ihl << 2));

  // compute_tcp_checksum(ip_info, (unsigned short*)tcpHeader);

  sum = 0;
  unsigned short tcpLen = newntohs(ip_info->tot_len) - (ip_info->ihl << 2);
  unsigned short *ipPayload = (unsigned short *)tcpHeader;
  struct tcphdr *tcphdrp = (struct tcphdr *)(ipPayload);
  //add the pseudo header
  //the source ip
  sum += (ip_info->saddr >> 16) & 0xFFFF;
  sum += (ip_info->saddr) & 0xFFFF;
  //the dest ip
  sum += (ip_info->daddr >> 16) & 0xFFFF;
  sum += (ip_info->daddr) & 0xFFFF;
  //protocol and reserved: 6
  sum += newhtons(IPPROTO_TCP);
  //the length
  sum += newhtons(tcpLen);

  //add the IP payload
  //initialize checksum to 0
  tcphdrp->check = 0;
  while (tcpLen > 1)
  {
      sum += *ipPayload++;
      tcpLen -= 2;
  }
  //if any bytes left, pad the bytes and add
  if (tcpLen > 0)
  {
      //printf("+++++++++++padding, %dn", tcpLen);
      sum += ((*ipPayload) & newhtons(0xFF00));
  }
  //Fold 32-bit sum to 16 bits: add carrier to result
  while (sum >> 16)
  {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  sum = ~sum;
  //set computation result
  tcphdrp->check = (unsigned short)sum;
  //TCP CHECKSUM CALCULATION ENDS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  //CHECKSUM CALCULATION ENDS -------------------------------------------------------------------------------
}
char* kernel_wrapper(char *buf)
{

  struct iphdr *ip_info;
  char *newBuf;
  int packetSize = 64 * (sizeof(char)); //Size of an ICMP packet is 64 so copying 64 bytes from the char pointer

  /*Basically there is no simple way of knowing what is the size of the packet and just copying till the sizeof(buf) simply doesn't work
  So right now copying 64 bytes (size of icmp packet, testing for ping) */

  newBuf = (char *)malloc(packetSize);

  // ip_info = (struct iphdr*)(newBuf + SIZE_ETHERNET);
  // printf("\nIN THE KERNEL WRAPPER FUNCTION BEFORE - %x\n",(ip_info->check));

  dim3 threads(1, 1); //change the threads to n,n (keep multiple of 64) to send n*n*n packets to the gpu
  dim3 blocks(1, 1); //similar configuration change as above
  char *d_newBuf;
  cudaMalloc((void **)&d_newBuf, packetSize);
  cudaMemcpy(d_newBuf, buf, packetSize, cudaMemcpyHostToDevice);
  cudaMemcpy(newBuf, d_newBuf, packetSize, cudaMemcpyDeviceToHost);

  ip_info = (struct iphdr *)(newBuf + SIZE_ETHERNET);
  printf("\nIN THE KERNEL WRAPPER FUNCTION AFTER - %x\n", (ip_info->check));

  nat<<<1, 10>>>(d_newBuf);
  cudaDeviceSynchronize();

  printf("\n~~~~CUDA Code Was Called. Finish Kernel Wrapper~~~~\n");
  cudaFree(d_newBuf);
  return newBuf;
}
