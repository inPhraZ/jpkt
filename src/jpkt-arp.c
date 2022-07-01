/*
 * =====================================================================================
 *
 *       Filename:  jpkt-arp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "jpkt-arp.h"

/*  ARP header
 *  ARP packets are variable in size
 *  this structure defines the fixed-length for ARPHRD_ETHER hardware */
typedef struct __jpkt_arphdr {
    uint16_t            ar_hrd;
    uint16_t            ar_pro;
    uint8_t             ar_hln;
    uint8_t             ar_pln;
    uint16_t            ar_op;
    struct  ether_addr  ar_sha;
    struct  in_addr     ar_sip;
    struct  ether_addr  ar_tha;
    struct  in_addr     ar_tip;
} __attribute__ ((__packed__)) arphdr_t;

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

static arp_t *arp_alloc()
{
    arp_t *arpptr = (arp_t *)malloc(sizeof(arp_t));
    if (!arpptr)
        return NULL;

    memset(arpptr, 0, sizeof(arp_t));
    return arpptr;
}

arp_t *arp_extract(const u_char *bytes)
{
    arp_t       *arpptr;
    arphdr_t    *arphdr;

    if (!bytes)
        return NULL;

    arpptr = arp_alloc();
    if (!arpptr)
        return NULL;

    arphdr = (arphdr_t *)bytes;

    uint16_t hrd = ntohs(arphdr->ar_hrd);
    uint16_t op = ntohs(arphdr->ar_op);

    arpptr->ar_hln = arphdr->ar_hln;
    arpptr->ar_pln = arphdr->ar_pln;

    snprintf(arpptr->ar_hrd, ARPHRDLEN,
            "%s", arp_hardware_ids[hrd]);
    snprintf(arpptr->ar_op, ARPOPLEN,
            "%s", arp_protocol_opcodes[op]);
    snprintf(arpptr->ar_pro, ARPPROLEN,
            "0x%x", ntohs(arphdr->ar_pro));
    snprintf(arpptr->ar_sha, ARPHALEN,
            "%s", ether_ntoa(&arphdr->ar_sha));
    snprintf(arpptr->ar_sip, ARPIPLEN,
            "%s", inet_ntoa(arphdr->ar_sip));
    snprintf(arpptr->ar_tha, ARPHALEN,
            "%s", ether_ntoa(&arphdr->ar_tha));
    snprintf(arpptr->ar_tip, ARPIPLEN,
            "%s", inet_ntoa(arphdr->ar_tip));

    return arpptr;
}
