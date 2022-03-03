/*
 * =====================================================================================
 *
 *       Filename:  packet.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef __REPONET_PACKET_H_
#define __REPONET_PACKET_H_     1

#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/queue.h>

/* Structure containing captured packet */
typedef struct __reponet_packet {
    size_t  len;                                /*  Length of message */
    char    *pktmsg;                            /* Packet info as JSON */
    STAILQ_ENTRY(__reponet_packet)   entries;
} packet_t;

/* Singly-linked Tail queue decleration for packet queue */
STAILQ_HEAD(__packet_queue, packet_t);
typedef struct __packet_queue PktQueue;

/* Allocate memory for a Packet and initialize it */
packet_t   *allocate_packet();

/* Analyze the packet */
packet_t   *analyze_packet(const struct pcap_pkthdr *h, const u_char *bytes);

/*  Free allocated memory and assign NULL to the pointer */
#define     free_packet(pkt)    \
    do { free(pkt->pktmsg); free(pkt); pkt = NULL; } while(0)

#endif  /*  __REPONET_PACKET_H_ */
