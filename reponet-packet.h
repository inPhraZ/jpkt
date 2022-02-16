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

#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/queue.h>

/* Structure containing captured packet */
typedef struct __reponet_packet {
    size_t  len;                                /*  Length of message */
    char    *pktmsg;                            /* Packet info as JSON */
    STAILQ_ENTRY(__reponet_packet)   entries;
} Packet, *Packetptr;

STAILQ_HEAD(packet_queue, Packet);

/* Allocate memory for a Packet and initialize it */
Packetptr   allocate_packet();

Packetptr   analyze_packet(const struct pcap_pkthdr *h, const u_char *bytes);

/*  Free allocated memory for Packet */
void        free_allocated_packet(Packetptr);

/*  Free allocated memory and assign NULL to the pointer */
/*  Use this */
#define     free_packet(pkt)    \
    do { free_allocated_packet(pkt); pkt = NULL; } while(0)

#if 0
u_int16_t ethernet_type(u_char *user, const u_char *bytes);
#endif

#endif  /*  __REPONET_PACKET_H_ */
