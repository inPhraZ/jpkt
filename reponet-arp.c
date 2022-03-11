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
#include <string.h>
#include <arpa/inet.h>
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

arp_t *arp_extract(const u_char *bytes)
{
    arp_t       *arpptr;
    arphdr_t    *arphdr;

    if (!bytes)
        return NULL;

    arpptr = (arp_t *)malloc(sizeof(arp_t));
    if (!arpptr)
        return NULL;

    memset(arpptr, 0, sizeof(arp_t));

    arphdr = (arphdr_t *)bytes;

    arpptr->hln = arphdr->ar_hln;
    arpptr->pln = arphdr->ar_pln;
    arpptr->op = htons(arphdr->ar_op);
    arpptr->hrd = htons(arphdr->ar_hrd);

    snprintf(arpptr->hrd_str, ARPHRDLEN,
            "%s", arp_hardware_ids[arpptr->hrd]);
    snprintf(arpptr->op_str, ARPOPLEN,
            "%s", arp_protocol_opcodes[arpptr->op]);
    snprintf(arpptr->pro, ARPPROLEN,
            "0x%x", htons(arphdr->ar_pro));
    snprintf(arpptr->sha, ARPHALEN,
            "%s", ether_ntoa(&arphdr->ar_sha));
    snprintf(arpptr->sip, ARPIPLEN,
            "%s", inet_ntoa(arphdr->ar_sip));
    snprintf(arpptr->tha, ARPHALEN,
            "%s", ether_ntoa(&arphdr->ar_tha));
    snprintf(arpptr->tip, ARPIPLEN,
            "%s", inet_ntoa(arphdr->ar_tip));

    return arpptr;
}
