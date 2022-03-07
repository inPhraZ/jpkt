/*
 * =====================================================================================
 *
 *       Filename:  reponet-ip.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef     __REPONET_IP_H_
#define     __REPONET_IP_H_ 1

#define IPVERSIONLEN    4
#define IPHDRLEN        3
#define IPTOSLEN        5
#define IPTOTALLEN      6
#define IPIDLEN         7
#define IPFLAGLEN       4
#define IPOFFLEN        7
#define IPTTLLEN        4
#define IPPROTOLEN      9
#define IPSUMLEN        7
#define IPADDRLEN       16

/*  IP header */
typedef struct __reponet_ip {
    uint8_t ip_p;
    char    version[IPVERSIONLEN];
    char    hlen[IPHDRLEN];
    char    tos[IPTOSLEN];
    char    tlen[IPTOTALLEN];
    char    id[IPIDLEN];
    char    flags[IPFLAGLEN];
    char    off[IPOFFLEN];
    char    ttl[IPTTLLEN];
    char    protocol[IPPROTOLEN];
    char    checksum[IPSUMLEN];
    char    saddr[IPADDRLEN];
    char    daddr[IPADDRLEN];
} ip_t;

/*  Allocate memory for ip header and extract data from bytes */
ip_t *ip_extract(const u_char *bytes);

/*  Free allocated memory and assign NULL to ipptr */
#define ip_free(ipptr)      \
    do { free(ipptr); ipptr = NULL; } while(0)

#endif      /*  __REPONET_IP_H_ */
