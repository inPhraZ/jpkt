/*
 * =====================================================================================
 *
 *       Filename:  jpkt-ip.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef     __REPONET_IP_H_
#define     __REPONET_IP_H_ 1

#include <json-glib/json-glib.h>

#define IPTOSLEN        5
#define IPIDLEN         7
#define IPFLAGLEN       4
#define IPOFFLEN        7
#define IPPROTOLEN      9
#define IPSUMLEN        7
#define IPADDRLEN       INET_ADDRSTRLEN

/*  IP header */
typedef struct __jpkt_ip {
    uint8_t     ip_v;
    uint8_t     ip_hl;
    char        ip_tos[IPTOSLEN];
    uint16_t    ip_len;
    char        ip_id[IPIDLEN];
    char        ip_flags[IPFLAGLEN];
    char        ip_off[IPOFFLEN];
    uint8_t     ip_ttl;
    uint8_t     ip_p;
    char        ip_protocol[IPPROTOLEN];
    char        ip_sum[IPSUMLEN];
    char        ip_src[IPADDRLEN];
    char        ip_dst[IPADDRLEN];
} ip_t;

/*  Allocate memory for ip header and extract data from bytes */
ip_t *ip_extract(const u_char *bytes);

/*  Analyze Upper layer of IPv4 */
int ip_upper(JsonBuilder *builder, const u_char *bytes,
        const uint8_t ip_p);

/*  Free allocated memory and assign NULL to ipptr */
#define ip_free(ipptr)      \
    do { free(ipptr); ipptr = NULL; } while(0)

#endif      /*  __REPONET_IP_H_ */
