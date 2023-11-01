/*
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap application to bridge two network interfaces,
 * or one interface and the host stack.
 *
 * $FreeBSD$
 */

#include "arpa/inet.h"
#include "checksum.h"
#include "firewall_kernels.h"
#include "linux/ip.h"
#include "nat.h"
#include "rules.h"
#include "sys/types.h"

#include <libnetmap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <time.h>
#include <unistd.h>

#if defined(_WIN32)
#define BUSYWAIT
#endif

struct timespec tic, toc;

unsigned long* ruleset;
unsigned int* nat_table;
unsigned long* nat_set;
int num_lines;
struct timespec time1;
static int verbose = 0;

static int do_abort = 0;
static int zerocopy = 1; /* enable zerocopy if possible */

static void sigint_h(int sig) {
    (void)sig; /* UNUSED */
    do_abort = 1;
    signal(SIGINT, SIG_DFL);
}

char *input_pkt_buf, *output_pkt_buf;
int len[1025];

/*
 * How many slots do we (user application) have on this
 * set of queues ?
 */
static int rx_slots_avail(struct nmport_d* d) {
    u_int i, tot = 0;

    for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
        tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
    }

    return tot;
}

static int tx_slots_avail(struct nmport_d* d) {
    u_int i, tot = 0;

    for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
        tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
    }

    return tot;
}

/*
 * Move up to 'limit' pkts from rxring to txring, swapping buffers
 * if zerocopy is possible. Otherwise fall back on packet copying.
 */
static int rings_move(struct netmap_ring* rxring, struct netmap_ring* txring, u_int limit, const char* msg) {
    u_int j, k, m = 0,iter,old_len = 0;;

    /* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
    if (rxring->flags || txring->flags)
        D("%s rxflags %x txflags %x", msg, rxring->flags, txring->flags);
    j = rxring->head; /* RX */
    k = txring->head; /* TX */
    m = nm_ring_space(rxring);
    if (m < limit)
        limit = m;
    m = nm_ring_space(txring);
    if (m < limit)
        limit = m;
    m = limit;
    while (limit-- > 0) {
        struct netmap_slot* rs = &rxring->slot[j];
        struct netmap_slot* ts = &txring->slot[k];

        if (ts->buf_idx < 2 || rs->buf_idx < 2) {
            RD(2, "wrong index rxr[%d] = %d  -> txr[%d] = %d", j, rs->buf_idx, k, ts->buf_idx);
        }
        /* Copy the packet length. */
        if (rs->len > rxring->nr_buf_size) {
            RD(2, "%s: invalid len %u, rxr[%d] -> txr[%d]", msg, rs->len, j, k);
            rs->len = 0;
        } else if (verbose > 1) {
            D("%s: fwd len %u, rx[%d] -> tx[%d]", msg, rs->len, j, k);
        }
        ts->len = rs->len;


        // char* rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
        
        // for (iter = 0; iter < rs->len; iter++) {
        //     input_pkt_buf[iter] = rxbuf[iter];//IMPP
        // }
        // nm_pkt_copy(rxbuf,input_pkt_buf,rs->len);
        // run_firewall(input_pkt_buf, output_pkt_buf, rs->len, limit, len[limit], ruleset, num_lines, nat_table, nat_set);


        // char* txbuf = NETMAP_BUF(txring, ts->buf_idx);
        // nm_pkt_copy(rxbuf, txbuf, ts->len);

        if (zerocopy) {
            uint32_t pkt = ts->buf_idx;
            ts->buf_idx  = rs->buf_idx;
            rs->buf_idx  = pkt;
            /* report the buffer change. */
            ts->flags |= NS_BUF_CHANGED;
            rs->flags |= NS_BUF_CHANGED;
        } else {
            char* rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
            char* txbuf = NETMAP_BUF(txring, ts->buf_idx);
            nm_pkt_copy(rxbuf, txbuf, ts->len);
        }
        /*
         * Copy the NS_MOREFRAG from rs to ts, leaving any
         * other flags unchanged.
         */
        ts->flags = (ts->flags & ~NS_MOREFRAG) | (rs->flags & NS_MOREFRAG);
        j         = nm_ring_next(rxring, j);
        k         = nm_ring_next(txring, k);
    }
    rxring->head = rxring->cur = j;
    txring->head = txring->cur = k;
    if (verbose && m > 0)
        D("%s fwd %d packets: rxring %u --> txring %u", msg, m, rxring->ringid, txring->ringid);

    return (m);
}

static int rings_process_move(struct netmap_ring* rxring, struct netmap_ring* txring, u_int limit, const char* msg) {
    u_int i, j, k, m = 0, iter, old_len = 0;
    u_int limit1, limit2;

    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("Started PKT FWD: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);

    /* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
    if (rxring->flags || txring->flags)
        D("%s rxflags %x txflags %x", msg, rxring->flags, txring->flags);
    j = rxring->head; /* RX */
    k = txring->head; /* TX */
    m = nm_ring_space(rxring);
    if (m < limit)
        limit = m;
    m = nm_ring_space(txring);
    if (m < limit)
        limit = m;
    m      = limit;
    limit1 = limit;
    limit2 = limit;
    i      = 0;
    len[0] = 0;
    while (limit1-- > 0) {
        struct netmap_slot* rs = &rxring->slot[j];
        // struct netmap_slot *ts = &txring->slot[k];

        /*if (ts->buf_idx < 2 || rs->buf_idx < 2) {
                RD(2, "wrong index rxr[%d] = %d  -> txr[%d] = %d",
                    j, rs->buf_idx, k, ts->buf_idx);
        }*/
        /* Copy the packet length. */
        /*if (rs->len > rxring->nr_buf_size) {
                RD(2,  "%s: invalid len %u, rxr[%d] -> txr[%d]",
                    msg, rs->len, j, k);
                rs->len = 0;
        } else if (verbose > 1) {
                D("%s: fwd len %u, rx[%d] -> tx[%d]",
                    msg, rs->len, j, k);
        }*/


        // ts->len = rs->len;
        len[i + 1] = rs->len + len[i];
        // printf("LEN %d %d \n",len[0],len[1]);

        char* rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
        // char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
        // nm_pkt_copy(rxbuf, txbuf, ts->len);
        // D("Came\n");
        
        // for (iter = 0; iter < rs->len; iter++) {
        //     input_pkt_buf[iter + old_len] = rxbuf[iter];//IMPP
        // }
        memcpy(&input_pkt_buf[old_len], rxbuf, rs->len);//try
        old_len += rs->len;
        i++;
        // D("DID??\n");
        /*
         * Copy the NS_MOREFRAG from rs to ts, leaving any
         * other flags unchanged.
         */
        // ts->flags = (ts->flags & ~NS_MOREFRAG) | (rs->flags & NS_MOREFRAG);
        j = nm_ring_next(rxring, j);
        // k = nm_ring_next(txring, k);
    }

    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("Just Before NMCPY: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);

     // run_firewall(input_pkt_buf, output_pkt_buf, len, limit, len[limit], ruleset, num_lines, nat_table, nat_set);
        // for(int count=0;count<len[limit];count++) {
    //  output_pkt_buf[count] = input_pkt_buf[count];
    // }
    // output_pkt_buf = input_pkt_buf;
    nm_pkt_copy(input_pkt_buf, output_pkt_buf, len[limit]);

    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("Just After NMCPY: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);


    /*printf("Done\n");
    printf("limit is %d\n", len[limit]);
    int ctr;
    for(ctr=1;ctr<len[limit];ctr++) {
            if (input_pkt_buf[ctr] != output_pkt_buf[ctr]) {
                    printf("Match failed at %d\n", ctr);
                    break;
            }
    }*/
    // usleep(50);
    i       = 0;
    old_len = 0;
    while (limit2-- > 0) {
        // struct netmap_slot *rs = &rxring->slot[j];
        struct netmap_slot* ts = &txring->slot[k];

        /*if (ts->buf_idx < 2 || rs->buf_idx < 2) {
                RD(2, "wrong index rxr[%d] = %d  -> txr[%d] = %d",
                    j, rs->buf_idx, k, ts->buf_idx);
        }*/
        /* Copy the packet length. */
        /*if (rs->len > rxring->nr_buf_size) {
                RD(2,  "%s: invalid len %u, rxr[%d] -> txr[%d]",
                    msg, rs->len, j, k);
                rs->len = 0;
        } else if (verbose > 1) {
                D("%s: fwd len %u, rx[%d] -> tx[%d]",
                    msg, rs->len, j, k);
        }*/

        ts->len = len[i + 1] - len[i];

        // char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
        char* txbuf = NETMAP_BUF(txring, ts->buf_idx);
        nm_pkt_copy(output_pkt_buf + old_len, txbuf, ts->len);
        old_len += len[i + 1] - len[i];
        i++;

        /*
         * Copy the NS_MOREFRAG from rs to ts, leaving any
         * other flags unchanged.
         */
        // ts->flags = (ts->flags & ~NS_MOREFRAG) | (rs->flags & NS_MOREFRAG);
        // j = nm_ring_next(rxring, j);
        k = nm_ring_next(txring, k);
    }

    rxring->head = rxring->cur = j;
    txring->head = txring->cur = k;
    if (verbose && m > 0)
        D("%s fwd %d packets: rxring %u --> txring %u", msg, m, rxring->ringid, txring->ringid);

    return (m);
}

/* Move packets from source port to destination port. */
static int ports_move(struct nmport_d* src, struct nmport_d* dst, u_int limit, const char* msg) {
    struct netmap_ring *txring, *rxring;
    u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;

    while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
        rxring = NETMAP_RXRING(src->nifp, si);
        txring = NETMAP_TXRING(dst->nifp, di);
        if (nm_ring_empty(rxring)) {
            si++;
            continue;
        }
        if (nm_ring_empty(txring)) {
            di++;
            continue;
        }
        m += rings_move(rxring, txring, limit, msg);
    }

    return (m);
}

static int ports_process_move(struct nmport_d* src, struct nmport_d* dst, u_int limit, const char* msg) {
    struct netmap_ring *txring, *rxring;
    u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;

    while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
        rxring = NETMAP_RXRING(src->nifp, si);
        txring = NETMAP_TXRING(dst->nifp, di);
        if (nm_ring_empty(rxring)) {
            si++;
            continue;
        }
        if (nm_ring_empty(txring)) {
            di++;
            continue;
        }

        m += rings_process_move(rxring, txring, limit, msg);
        // m += rings_move(rxring, txring, limit, msg);
    }

    return (m);
}

static void usage(void) {
    fprintf(stderr,
            "netmap bridge program: forward packets between two "
            "netmap ports\n"
            "    usage(1): bridge [-v] [-i ifa] [-i ifb] [-b burst] "
            "[-w wait_time] [-L]\n"
            "    usage(2): bridge [-v] [-w wait_time] [-L] "
            "[ifa [ifb [burst]]]\n"
            "\n"
            "    ifa and ifb are specified using the nm_open() syntax.\n"
            "    When ifb is missing (or is equal to ifa), bridge will\n"
            "    forward between between ifa and the host stack if -L\n"
            "    is not specified, otherwise loopback traffic on ifa.\n"
            "\n"
            "    example: bridge -w 10 -i netmap:eth3 -i netmap:eth1\n"
            "\n"
            "    If ifa and ifb are two interfaces, they must be in\n"
            "    promiscuous mode. Otherwise, if bridging with the \n"
            "    host stack, the interface must have the offloads \n"
            "    disabled.\n");
    exit(1);
}

/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 * two intefaces.
 */
int main(int argc, char** argv) {
    char msg_a2b[256], msg_b2a[256];
    struct pollfd pollfd[2];
    u_int burst = 1024, wait_link = 4;
    struct nmport_d *pa = NULL, *pb = NULL;
    char *ifa = NULL, *ifb = NULL;
    char ifabuf[64] = { 0 };
    int pa_sw_rings, pb_sw_rings;
    int loopback = 0;
    int ch;
    int iter = 0;
    len[0]   = 0;

    
    // input_pkt_buf  = (char*)malloc(1518 * 1024 * sizeof(char));
    // output_pkt_buf = (char*)malloc(1518 * 1024 * sizeof(char));
    // cudaMallocManaged(&input_pkt_buf, 1518 * 1024  * sizeof(char));
    // cudaMallocManaged(&output_pkt_buf, 1518 * 1024  * sizeof(char));
    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("NM start: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);

    fprintf(stderr, "%s built %s %s\n\n", argv[0], __DATE__, __TIME__);

    while ((ch = getopt(argc, argv, "hb:ci:vw:L")) != -1) {
        switch (ch) {
            default:
                D("bad option %c %s", ch, optarg);
                /* fallthrough */
            case 'h':
                usage();
                break;
            case 'b': /* burst */
                burst = atoi(optarg);
                break;
            case 'i': /* interface */
                if (ifa == NULL)
                    ifa = optarg;
                else if (ifb == NULL)
                    ifb = optarg;
                else
                    D("%s ignored, already have 2 interfaces", optarg);
                break;
            case 'c':
                zerocopy = 0; /* do not zerocopy */
                break;
            case 'v':
                verbose++;
                break;
            case 'w':
                wait_link = atoi(optarg);
                break;
            case 'L':
                loopback = 1;
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc > 0)
        ifa = argv[0];
    if (argc > 1)
        ifb = argv[1];
    if (argc > 2)
        burst = atoi(argv[2]);
    if (!ifb)
        ifb = ifa;
    if (!ifa) {
        D("missing interface");
        usage();
    }
    if (burst < 1 || burst > 8192) {
        D("invalid burst %d, set to 1024", burst);
        burst = 1024;
    }
    if (wait_link > 100) {
        D("invalid wait_link %d, set to 4", wait_link);
        wait_link = 4;
    }
    if (!strcmp(ifa, ifb)) {
        if (!loopback) {
            D("same interface, endpoint 0 goes to host");
            snprintf(ifabuf, sizeof(ifabuf) - 1, "%s^", ifa);
            ifa = ifabuf;
        } else {
            D("same interface, loopbacking traffic");
        }
    } else {
        /* two different interfaces. Take all rings on if1 */
    }
    pa = nmport_open(ifa);
    if (pa == NULL) {
        D("cannot open %s", ifa);
        return (1);
    }
    /* try to reuse the mmap() of the first interface, if possible */
    pb = nmport_open(ifb);
    if (pb == NULL) {
        D("cannot open %s", ifb);
        nmport_close(pa);
        return (1);
    }
    zerocopy = zerocopy && (pa->mem == pb->mem);
    D("------- zerocopy %ssupported", zerocopy ? "" : "NOT ");

    /* setup poll(2) array */
    memset(pollfd, 0, sizeof(pollfd));
    pollfd[0].fd = pa->fd;
    pollfd[1].fd = pb->fd;

    num_lines = load_rules("test_ruleset_nowildcards.csv", &ruleset);
    // printf("Here after load rules.\n");
    allocate_nat_table(&nat_table);
    allocate_nat_set(&nat_set);
    allocate_buf(&input_pkt_buf);
    allocate_buf(&output_pkt_buf);

    // clock_gettime(CLOCK_MONOTONIC, &time1);
    // printf("Malloc Done: %ld s\n", time1.tv_sec*1000000000L + time1.tv_nsec);

    D("Wait %d secs for link to come up...", wait_link);
    sleep(wait_link);
    D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.",
      pa->hdr.nr_name,
      pa->first_rx_ring,
      pa->reg.nr_rx_rings,
      pb->hdr.nr_name,
      pb->first_rx_ring,
      pb->reg.nr_rx_rings);

    pa_sw_rings = (pa->reg.nr_mode == NR_REG_SW || pa->reg.nr_mode == NR_REG_ONE_SW);
    pb_sw_rings = (pb->reg.nr_mode == NR_REG_SW || pb->reg.nr_mode == NR_REG_ONE_SW);

    snprintf(msg_a2b,
             sizeof(msg_a2b),
             "%s:%s --> %s:%s",
             pa->hdr.nr_name,
             pa_sw_rings ? "host" : "nic",
             pb->hdr.nr_name,
             pb_sw_rings ? "host" : "nic");

    snprintf(msg_b2a,
             sizeof(msg_b2a),
             "%s:%s --> %s:%s",
             pb->hdr.nr_name,
             pb_sw_rings ? "host" : "nic",
             pa->hdr.nr_name,
             pa_sw_rings ? "host" : "nic");

    int num_pkts = 0, pkt_iter = 0;

    /* main loop */
    signal(SIGINT, sigint_h);
    while (!do_abort) {
        // clock_gettime(CLOCK_MONOTONIC_RAW, &tic);
        int n0 = 0, n1 = 0, ret;
        pollfd[0].events = pollfd[1].events = 0;
        pollfd[0].revents = pollfd[1].revents = 0;
        n0                                    = rx_slots_avail(pa);
        n1                                    = rx_slots_avail(pb);
#ifdef BUSYWAIT
        if (n0) {
            pollfd[1].revents = POLLOUT;
        } else {
            ioctl(pollfd[0].fd, NIOCRXSYNC, NULL);
        }
        if (n1) {
            pollfd[0].revents = POLLOUT;
        } else {
            ioctl(pollfd[1].fd, NIOCRXSYNC, NULL);
        }
        ret = 1;
#else  /* !defined(BUSYWAIT) */
        // if (n0 > 1023 || (iter > 1500 && n0 != 0)) {
        if (n0) {
            // printf("Num pkts: %d\n", n0);
            num_pkts += n0;
            pkt_iter++;
            // printf("Average pkt size: %d\n", num_pkts/pkt_iter);
            pollfd[1].events |= POLLOUT;
            iter = 0;
        } else
            pollfd[0].events |= POLLIN;
        if (n1)
            pollfd[0].events |= POLLOUT;
        else
            pollfd[1].events |= POLLIN;

        /* poll() also cause kernel to txsync/rxsync the NICs */
        ret = poll(pollfd, 2, 2500);
#endif /* !defined(BUSYWAIT) */
        if (ret <= 0 || verbose)
            D("poll %s [0] ev %x %x rx %d@%d tx %d,"
              " [1] ev %x %x rx %d@%d tx %d",
              ret <= 0 ? "timeout" : "ok",
              pollfd[0].events,
              pollfd[0].revents,
              rx_slots_avail(pa),
              NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->head,
              tx_slots_avail(pa),
              pollfd[1].events,
              pollfd[1].revents,
              rx_slots_avail(pb),
              NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->head,
              tx_slots_avail(pb));
        if (ret < 0)
            continue;
        if (pollfd[0].revents & POLLERR) {
            struct netmap_ring* rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);
            D("error on fd0, rx [%d,%d,%d)", rx->head, rx->cur, rx->tail);
        }
        if (pollfd[1].revents & POLLERR) {
            struct netmap_ring* rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
            D("error on fd1, rx [%d,%d,%d)", rx->head, rx->cur, rx->tail);
        }
        if (pollfd[0].revents & POLLOUT) {
            ports_process_move(pb, pa, burst, msg_b2a);
#ifdef BUSYWAIT
            ioctl(pollfd[0].fd, NIOCTXSYNC, NULL);
#endif
        }

        if (pollfd[1].revents & POLLOUT) {
            ports_process_move(pa, pb, burst, msg_a2b);
            // ports_move(pa, pb, burst, msg_a2b);
#ifdef BUSYWAIT
            ioctl(pollfd[1].fd, NIOCTXSYNC, NULL);
#endif
        }

        /*
         * We don't need ioctl(NIOCTXSYNC) on the two file descriptors.
         * here. The kernel will txsync on next poll().
         */
        // iter++;
        // clock_gettime(CLOCK_MONOTONIC_RAW, &toc);

        // printf ("Total time = %ld nanoseconds\n", (toc.tv_nsec - tic.tv_nsec));
    }
    nmport_close(pb);
    nmport_close(pa);

    // free(input_pkt_buf);
    // free(output_pkt_buf);
    // cudaFree(input_pkt_buf);
    // cudaFree(output_pkt_buf);
    free_buf(input_pkt_buf);
    free_buf(output_pkt_buf);
    free_rules(ruleset);
    free_nat(nat_table, nat_set);

    return (0);
}

