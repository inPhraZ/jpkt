/*
 * =====================================================================================
 *
 *       Filename:  packet.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef __JPACKET_PACKET_H_
#define __JPACKET_PACKET_H_     1

#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/queue.h>

/* Structure containing captured packet */
typedef struct __jpkt_packet {
    size_t  len;                                /*  Length of message */
    char    *pktmsg;                            /* Packet info as JSON */
    STAILQ_ENTRY(__jpkt_packet)   entries;
} packet_t;

/* Singly-linked Tail queue decleration for packet queue */
STAILQ_HEAD(__packet_queue, __jpkt_packet);
typedef struct __packet_queue jpkt_queue;

/* Analyze the packet */
packet_t   *packet_extract(const struct pcap_pkthdr *h, const u_char *bytes);

/*  Free allocated memory and assign NULL to the pointer */
#define     packet_free(pkt)    \
    do { free(pkt->pktmsg); free(pkt); pkt = NULL; } while(0)

#endif  /*  __JPACKET_PACKET_H_ */
