#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <sys/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define IP_HL(ip) (((ip)->ihl) & 0x0f)

int main(int argc, char** argv) {
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t* handle1;
    pcap_t* handle2;

    int total_packet_count = 1000, i, j, size_ip;

    const u_char* pkt_data1 = NULL;
    const u_char* pkt_data2 = NULL;

    struct pcap_pkthdr* pcap_header1;
    struct pcap_pkthdr* pcap_header2;

    struct tcphdr *if1_tcp, *if2_tcp;
    struct iphdr *if1_ip, *if2_ip;

    long secs, usecs;

    /* device and snapshot_length are not used when opening a file */
    handle1 = pcap_open_offline_with_tstamp_precision("/home/fenrir/10int.pcap", PCAP_TSTAMP_PRECISION_NANO, error_buffer);
    handle2 = pcap_open_offline_with_tstamp_precision("/home/fenrir/20int.pcap", PCAP_TSTAMP_PRECISION_NANO, error_buffer);

    for (i = 0; i < total_packet_count; i++) {
        if (pcap_next_ex(handle2, &pcap_header2, &pkt_data2) == 1) {
            if2_ip = (struct iphdr*)(pkt_data2 + 14);

            size_ip = IP_HL(if2_ip) * 4;

            if (size_ip < 20) {
                printf("* Invalid IP header length: %u bytes\n", size_ip);
                return 0;
            }

            if2_tcp = (struct tcphdr*)(pkt_data2 + 14 + size_ip);

            for (j = 0; j < total_packet_count; j++) {
                if (pcap_next_ex(handle1, &pcap_header1, &pkt_data1) == 1) {
                    if1_ip  = (struct iphdr*)(pkt_data1 + 14);
                    size_ip = IP_HL(if1_ip) * 4;

                    if (size_ip < 20) {
                        printf("* Invalid IP header length: %u bytes\n", size_ip);
                        return 0;
                    }

                    if1_tcp = (struct tcphdr*)(pkt_data1 + 14 + size_ip);

                    if (ntohl(if1_tcp->seq) == ntohl(if2_tcp->seq)) {
                        printf("Seq1: %ld Seq2: %ld\n\n", ntohl(if1_tcp->seq), ntohl(if2_tcp->seq));
                        printf("Source: %hu Destination: %hu\n\n", ntohs(if1_tcp->source), ntohs(if1_tcp->dest));

                        secs  = pcap_header1->ts.tv_sec - pcap_header2->ts.tv_sec;
                        usecs = pcap_header1->ts.tv_usec - pcap_header2->ts.tv_usec;

                        printf("Interval = %ld\n\n", secs * 1000 + usecs);
                    }
                }
            }
        }
    }

    return 0;
}
