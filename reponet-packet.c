/*
 * =====================================================================================
 *
 *       Filename:  packet.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "reponet-packet.h"


Packetptr allocate_packet()
{
    Packetptr pktptr;
    pktptr = (Packetptr)malloc(sizeof(Packet));
    if (!pktptr)
        return NULL;
    memset(pktptr, 0, sizeof(Packet));
    return pktptr;
}

Packetptr   analyze_packet(const struct pcap_pkthdr *h, const u_char *bytes)
{
    Packetptr pktptr;
    pktptr = allocate_packet();
    if (!pktptr) {
        perror("allocate_packet");
        return NULL;
    }
    /*-----------------------------------------------------------------------------
     * TODO: analyze the packet
     *-----------------------------------------------------------------------------*/
    return pktptr;
}

#if 0
u_int16_t ethernet_type(u_char *user, const u_char *bytes)
{
    u_int16_t type;
    struct ether_header *ehp;

    ehp = (struct ether_header *)bytes;
    type = ntohs(ehp->ether_type);
    return type;
}

#endif
