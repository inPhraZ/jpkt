/*
 * =====================================================================================
 *
 *       Filename:  reponet-icmp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stddef.h>
#include <netinet/ip_icmp.h>

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

static const char *icmp_unreach_codes[] = {
    [ICMP_NET_UNREACH]      "Network Unreachable",
    [ICMP_HOST_UNREACH]     "Host Unreachable",
    [ICMP_PROT_UNREACH]     "Protocol Unreachable",
    [ICMP_PORT_UNREACH]     "Port Unreachable",
    [ICMP_FRAG_NEEDED]      "Fragmentation Needed",
    [ICMP_SR_FAILED]        "Source Route Failed",
    [ICMP_NET_UNKNOWN]      "Network Unknown",
    [ICMP_HOST_UNKNOWN]     "Host Unknown",
    [ICMP_HOST_ISOLATED]    "Host Isolated",
    [ICMP_NET_ANO]          "Network Prohibited",
    [ICMP_HOST_ANO]         "Host Prohibited",
    [ICMP_NET_UNR_TOS]      "Network Unreachable for TOS",
    [ICMP_HOST_UNR_TOS]     "Host unreachable for TOS",
    [ICMP_PKT_FILTERED]     "Packet Filtered",
    [ICMP_PREC_VIOLATION]   "Precedence Violation",
    [ICMP_PREC_CUTOFF]      "Precedence Cut Off"
};

static const char *icmp_redirect_codes[] = {
    [ICMP_REDIR_NET]        "Redirect Net",
    [ICMP_REDIR_HOST]       "Redirect Host",
    [ICMP_REDIR_NETTOS]     "Redirect Net for TOS",
    [ICMP_REDIR_HOSTTOS]    "Redirect Host for TOS"
};

static const char *icmp_time_exceeded_codes[] = {
    [ICMP_EXC_TTL]          "TTL count exceeded",
    [ICMP_EXC_FRAGTIME]     "Fragment time exceeded"
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
