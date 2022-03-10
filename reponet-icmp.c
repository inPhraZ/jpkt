/*
 * =====================================================================================
 *
 *       Filename:  reponet-icmp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include "reponet-icmp.h"

icmp_t *icmp_extract(const u_char *bytes)
{
    icmp_t *icmpptr;
    struct icmphdr *icmp_header;

    if (!bytes)
        return NULL;

    icmpptr = (icmp_t *)malloc(sizeof(icmp_t));
    if (!icmpptr)
        return NULL;

    icmp_header = (struct icmphdr *)bytes;

    return icmpptr;
}
