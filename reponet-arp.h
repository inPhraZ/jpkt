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

#define     ARPHRDLEN   11
#define     ARPPROLEN   6
#define     ARPHLNLEN   4
#define     ARPPLNLEN   4
#define     ARPOPLEN    6
#define     ARPHALEN    18
#define     ARPIPLEN    16

/*  ARP header
 *  ARP packets are variable in size
 *  this structure defines the fixed-length for ARPHRD_ETHER hardware */
typedef struct __reponet_arphdr {
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

/*  ARP header data as string values */
typedef struct __reponet_arp {
    char    hrd[ARPHRDLEN];
    char    pro[ARPPROLEN];
    char    hln[ARPHLNLEN];
    char    pln[ARPPLNLEN];
    char    op[ARPOPLEN];
    char    sha[ARPHALEN];
    char    sip[ARPIPLEN];
    char    tha[ARPHALEN];
    char    tip[ARPIPLEN];
} arp_t;

/*  Allocate memory for arp_t and 
 *  extract arp header from bytes */
arp_t   *arp_extract(const u_char *bytes);

/*  Free allocated memory and assign NULL to the arpptr */
#define     arp_free(arpptr)        \
    do { free(arpptr); arpptr = NULL; } while(0)

#endif      /*  __REPONET_ARP_H_ */
