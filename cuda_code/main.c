#include "b.h"
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#define SIZE_ETHERNET 14

extern char* kernel_wrapper(char *buf);

static unsigned short compute_checksum(unsigned short *addr, unsigned int count)
{
	register unsigned long sum = 0;
	while (count > 1)
	{
		sum += *addr++;
		count -= 2;
	}
	//if any bytes left, pad the bytes and add
	if (count > 0)
	{
		sum += ((*addr) & htons(0xFF00));
	}
	//Fold sum to 16 bits: add carrier to result
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	//one's complement
	sum = ~sum;
	return ((unsigned short)sum);
}
void compute_ip_checksum(struct iphdr *iphdrp)
{
	iphdrp->check = 0;
	printf("\nTHE CHECKSUM IS %x \n", iphdrp->check);

	iphdrp->check = compute_checksum((unsigned short *)iphdrp, iphdrp->ihl << 2);
	printf("\nTHE CHECKSUM IS %x \n", iphdrp->check);
}
//-------------------_TCP CHECKSUM-------------------------------------------------------
/* set tcp checksum: given IP header and tcp segment */
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
	register unsigned long sum = 0;
	unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
	struct tcphdr *tcphdrp = (struct tcphdr *)(ipPayload);
	//add the pseudo header
	//the source ip
	sum += (pIph->saddr >> 16) & 0xFFFF;
	sum += (pIph->saddr) & 0xFFFF;
	//the dest ip
	sum += (pIph->daddr >> 16) & 0xFFFF;
	sum += (pIph->daddr) & 0xFFFF;
	//protocol and reserved: 6
	sum += htons(IPPROTO_TCP);
	//the length
	sum += htons(tcpLen);

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
		sum += ((*ipPayload) & htons(0xFF00));
	}
	//Fold 32-bit sum to 16 bits: add carrier to result
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = ~sum;
	//set computation result
	tcphdrp->check = (unsigned short)sum;
}
static int
filter_packet(char *buf, int len)
{

	struct iphdr *ip_info;
	u_int size_ip;
	ip_info = (struct iphdr *)(buf + SIZE_ETHERNET);
	char source[16];
	__u32 *sa;
	sa = (__u32 *)source;
	*sa = ntohl(ip_info->saddr);

	char *processedBuf; //This is the variable that is for the processed packet from cuda wrapper program.

	if (ip_info->protocol == 1) //For ICMP, Use 17 for UDP and 6 for TCP 
	{

		//~~~The CUDA code is being called here using a wrapper function
		processedBuf=	kernel_wrapper(buf);
		*buf=*processedBuf; //Buf (the packet intended to go forward) is now replaced by the contents of processedBuf

		ip_info = (struct iphdr *)(buf + SIZE_ETHERNET);
		printf("\nprotocol %u", ip_info->protocol);
		printf("\nsource ip %x", ntohl(ip_info->saddr));
		printf("\ndestination  ip %x", ntohl(ip_info->daddr));
		printf("\nPROCESSED AFTER CHECKSUM %x", (ip_info->check));

		/*
		__u32 *newDest;
		newDest = malloc(sizeof(__u32));

		*newDest = inet_addr("20.0.0.2");
		ip_info->daddr=*newDest;
		printf("\ndestination changed ip %x", ntohl(ip_info->daddr));
		compute_ip_checksum(ip_info);
		struct tcphdr *tcpHeader;
		if (ip_info->protocol == IPPROTO_TCP)
		{ //FOR TCP PACKETS
			tcpHeader = (struct tcphdr *)(buf + SIZE_ETHERNET + (ip_info->ihl << 2));
			// compute_tcp_checksum(ip_info, (unsigned short*)tcpHeader);
		}
		*/
		printf("\niplen %d", ip_info->tot_len);
	}

	// Allow anything else
	return 1;
}

static void
receiver(struct nm_desc *d, unsigned int ring_id)
{
	struct pollfd fds;
	struct netmap_ring *ring;
	unsigned int i, len;
	char *buf;
	time_t now;
	int pps;
	printf("passed here");

	now = time(NULL);
	pps = 0;

	while (1)
	{
		fds.fd = d->fd;
		fds.events = POLLIN;

		int r = poll(&fds, 1, 1);
		if (r < 0)
		{
			perror("poll()");
			exit(3);
		}

		if (time(NULL) > now)
		{
			printf("[+] receiving %d pps\n", pps);
			pps = 0;
			now = time(NULL);
		}
		int ri = d->cur_rx_ring;

		ring = NETMAP_RXRING(d->nifp, ri);
		// struct	nm_pkthdr h;
		while (!nm_ring_empty(ring))
		{
			i = ring->cur;
			u_int idx = ring->slot[i].buf_idx;
			// printf("\nbuffer size is %d\n", strlen(buf));

			buf = (char *)NETMAP_BUF(ring, idx);
			// printf("\nbuffer size is %d\n",n(buf));
			len = ring->slot[i].len;

			pps++;

			if (filter_packet(buf, len))
			{
				// if (1) {
				// forward
				ring->flags |= NR_FORWARD;
				ring->slot[i].flags |= NS_FORWARD;
			}
			else
			{
				// drop
			}

			ring->head = ring->cur = nm_ring_next(ring, i);
			// ring->head = ring->cur;
			d->cur_rx_ring = ri;
		}
	}
}

int main(int argc, char *argv[])
{
	char netmap_ifname[64];
	const char *interface;
	unsigned int ring_id;
	struct nm_desc *d;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
		exit(1);
	}

	interface = argv[1];
	// ring_id   = atoi(argv[2]);

	snprintf(netmap_ifname, sizeof(netmap_ifname), "netmap:%s/R", interface);

	d = nm_open(netmap_ifname, NULL, 0, 0);

	if (!d)
	{
		perror("nm_open()");
		exit(2);
	}

	//printf("[+] Receiving packets on interface %s, RX ring %d\n", interface, ring_id);
	printf("passed here");
	receiver(d, ring_id);

	return 0;
}
