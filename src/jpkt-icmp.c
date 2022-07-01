/*
 * =====================================================================================
 *
 *       Filename:  jpkt-icmp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <netinet/ip_icmp.h>

#include "jpkt-icmp.h"

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

static char *icmp_get_code(const uint8_t type, const uint8_t code)
{
    char *code_str = NULL;
    switch (type) {
        case ICMP_DEST_UNREACH:
            code_str = strdup(icmp_unreach_codes[code]);
            break;
        case ICMP_REDIRECT:
            code_str = strdup(icmp_redirect_codes[code]);
            break;
        case ICMP_TIME_EXCEEDED:
            code_str = strdup(icmp_time_exceeded_codes[code]);
            break;
        default:
            code_str = (char *)malloc(1);
            memset(code_str, 0, 1);
            break;
    }
    return code_str;
}

icmp_t *icmp_extract(const u_char *bytes)
{
    icmp_t *icmpptr;
    struct icmphdr *icmp_header;

    if (!bytes)
        return NULL;

    icmpptr = (icmp_t *)malloc(sizeof(icmp_t));
    if (!icmpptr)
        return NULL;
    memset(icmpptr, 0, sizeof(icmp_t));

    icmp_header = (struct icmphdr *)bytes;

    uint8_t type = icmp_header->type;
    uint8_t code = icmp_header->code;

    icmpptr->type = type;
    icmpptr->code = code;
    icmpptr->type_str = strdup(icmp_types[type]);
    icmpptr->code_str = icmp_get_code(type, code);

    snprintf(icmpptr->checksum, ICMPSUMLEN,
            "0x%04x", ntohs(icmp_header->checksum));

    return icmpptr;
}
