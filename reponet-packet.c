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
