/*
 * =====================================================================================
 *
 *       Filename:  reponet-arp.h
 *         Author:  Farzin
 *
 * =====================================================================================
 */

#ifndef     __REPONET_ARP_H_
#define     __REPONET_ARP_H_    1

#include <stdint.h>
#include <netinet/in.h>
#include <net/ethernet.h>

typedef struct __reponet_arphdr {
    uint16_t            ar_hrd;
    uint16_t            ar_pro;
    uint8_t             ar_hln;
    uint8_t             ar_pln;
    uint16_t            ar_op;
    struct ether_addr   ar_sha;
    struct in_addr      ar_sip;
    struct ether_addr   ar_tha;
    struct in_addr  ar_tip;
} __attribute__ ((__packed__)) arphdr_t;

#if 0
typedef struct __reponet_arp {
} arp_t;

arp_t   *arp_extract(const u_char *bytes);
#endif

#endif      /*  __REPONET_ARP_H_ */
