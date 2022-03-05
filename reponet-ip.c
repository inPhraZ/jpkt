/*
 * =====================================================================================
 *
 *       Filename:  reponet-ip.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "reponet-ip.h"

ip_t *ip_extract(const u_char *bytes)
{
    ip_t *ipptr;
    struct ip *ip_header;
    unsigned short fl_off;

    if (!bytes)
        return NULL;

    ipptr = (ip_t *)malloc(sizeof(ip_t));
    if (!ipptr)
        return NULL;

    memset(ipptr, 0, sizeof(ip_t));
    ip_header = (struct ip*)(bytes);

    snprintf(ipptr->version, IPVERSIONLEN,
            "%d", ip_header->ip_v);
    snprintf(ipptr->hlen, IPHDRLEN,
            "%d", ip_header->ip_hl * 4);
    snprintf(ipptr->tos, IPTOSLEN,
            "0x%x", ip_header->ip_tos);
    snprintf(ipptr->tlen, IPTOTALLEN,
            "%d", ntohs(ip_header->ip_len));
    snprintf(ipptr->id, IPIDLEN,
            "0x%x", ntohs(ip_header->ip_id));

    /* 
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |Flags|    Fragment Offset      |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    fl_off = ntohs(ip_header->ip_off);
    snprintf(ipptr->flags, IPFLAGLEN,
            "0x%x", (fl_off & (~IP_OFFMASK)) >> 13);
    snprintf(ipptr->off, IPOFFLEN,
            "0x%x", (fl_off & IP_OFFMASK));

    snprintf(ipptr->ttl, IPTTLLEN,
            "%d", ip_header->ip_ttl);
    snprintf(ipptr->protocol, IPPROTOLEN,
            "%d", ip_header->ip_p);
    snprintf(ipptr->checksum, IPSUMLEN,
            "0x%x", ntohs(ip_header->ip_sum));
    snprintf(ipptr->saddr, IPADDRLEN,
            "%s", inet_ntoa(ip_header->ip_src));
    snprintf(ipptr->daddr, IPADDRLEN,
            "%s", inet_ntoa(ip_header->ip_dst));

    return ipptr;
}
