#ifndef CHECKSUM_H
#define CHECKSUM_H

void compute_ip_checksum(struct iphdr* iphdrp);

void compute_tcp_checksum(struct iphdr* pIph, unsigned short* ipPayload);

#endif
