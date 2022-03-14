/*
 * =====================================================================================
 *
 *       Filename:  jpkt-arp.h
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
#define     ARPPROLEN   7
#define     ARPOPLEN    14
#define     ARPHALEN    18
#define     ARPIPLEN    INET_ADDRSTRLEN

/*  ARP header (for json builder) */
typedef struct __jpkt_arp {
    char        ar_hrd[ARPHRDLEN];
    char        ar_pro[ARPPROLEN];
    uint8_t     ar_hln;
    uint8_t     ar_pln;
    char        ar_op[ARPOPLEN];
    char        ar_sha[ARPHALEN];
    char        ar_sip[ARPIPLEN];
    char        ar_tha[ARPHALEN];
    char        ar_tip[ARPIPLEN];
} arp_t;

/*  Allocate memory for arp_t and 
 *  extract arp header from bytes */
arp_t   *arp_extract(const u_char *bytes);

/*  Free allocated memory and assign NULL to the arpptr */
#define     arp_free(arpptr)        \
    do { free(arpptr); arpptr = NULL; } while(0)

#endif      /*  __REPONET_ARP_H_ */
