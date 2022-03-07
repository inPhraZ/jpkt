/*
 * =====================================================================================
 *
 *       Filename:  reponet-arp.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  03/07/2022 01:07:15 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <netinet/ether.h>

#include "reponet-arp.h"

/*  ARP protocol hardware identifiers. */
static const char *arp_hardware_ids[] = {
    [ARPHRD_NETROM]     "NetRom",
    [ARPHRD_ETHER]      "Ethernet",
    [ARPHRD_EETHER]     "EEthernet",
    [ARPHRD_AX25]       "AX25",
    [ARPHRD_PRONET]     "PROnet",
    [ARPHRD_CHAOS]      "Chaosnet",
    [ARPHRD_IEEE802]    "IEEE802",
    [ARPHRD_ARCNET]     "ARCnet",
    [ARPHRD_APPLETLK]   "AppleTalk",
    [ARPHRD_DLCI]       "DLCI",
    [ARPHRD_ATM]        "ATM",
    [ARPHRD_METRICOM]   "Metricom",
    [ARPHRD_IEEE1394]   "IEEE1394",
    [ARPHRD_EUI64]      "EUI-64",
    [ARPHRD_INFINIBAND] "Infiniband"
};

/*  ARP protocol opcodes. */
static const char *arp_protocol_opcodes[] = {
    [ARPOP_REQUEST]     "request",
    [ARPOP_REPLY]       "reply",
    [ARPOP_RREQUEST]    "RARP request",
    [ARPOP_RREPLY]      "RARP reply",
    [ARPOP_InREQUEST]   "InARP request",
    [ARPOP_InREPLY]     "InARP reply",
    [ARPOP_NAK]         "NAK"
};
