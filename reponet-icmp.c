/*
 * =====================================================================================
 *
 *       Filename:  reponet-icmp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include "reponet-icmp.h"

static const char *icmp_types[] = {
    [ICMP_ECHOREPLY]        "Echo Reply",
    [ICMP_DEST_UNREACH]     "Destination Unreachable",
    [ICMP_SOURCE_QUENCH]    "Source Quench",
    [ICMP_REDIRECT]         "Redirect",
    [ICMP_ECHO]             "Echo Request",
    [ICMP_TIME_EXCEEDED]    "Time Exceeded",
    [ICMP_PARAMETERPROB]    "Parameter Problem",
    [ICMP_TIMESTAMP]        "Timestamp Request",
    [ICMP_TIMESTAMPREPLY]   "Timestamp Reply",
    [ICMP_INFO_REQUEST]     "Information Request",
    [ICMP_INFO_REPLY]       "Information Reply",
    [ICMP_ADDRESS]          "Address Mask Request",
    [ICMP_ADDRESSREPLY]     "Address Mask Reply"
};

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
