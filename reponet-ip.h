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
#define IPOFFLEN        2
#define IPADDRLEN       16

typedef struct __reponet_ip {
    char version[IPVERSIONLEN];
    char hlen[IPHDRLEN];
    char tos[IPTOSLEN];
    char tlen[IPTOTALLEN];
    char id[IPIDLEN];
    char flags[IPFLAGLEN];
    char off[IPOFFLEN];
    char saddr[IPADDRLEN];
    char daddr[IPADDRLEN]
} ip_t;

#endif      /*  __REPONET_IP_H_ */
