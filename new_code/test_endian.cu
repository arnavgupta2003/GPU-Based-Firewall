#include <stdio.h>
#include <arpa/inet.h>

__global__ void endian(unsigned int x) {
	// __builtin_bswap16(x);
}

int main()
{
	unsigned short num = 45;
	unsigned short swapped = (num>>8) | (num<<8);
	printf("%d\n", swapped);
	printf("%d\n", ntohs(45));
	/* code */
	return 0;
}