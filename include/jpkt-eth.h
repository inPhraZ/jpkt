/*
 * =====================================================================================
 *
 *       Filename:  jpkt-eth.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef     __JPACKET_ETHERNET_H_
#define     __JPACKET_ETHERNET_H_   1

#include <stdint.h>

/*  Ethernet header */
typedef struct __jpkt_ethernet {
    uint16_t    type;
    char        *dhost_str;
    char        *shost_str;
    char        *type_str;
} ethernet_t;

/*  Allocate memory for Ethernet and
 *  extract data from bytes */
ethernet_t     *ethernet_extract(const u_char *bytes);

/*  Free allocated memory and assign NULL to the pointer */
#define     ethernet_free(ethp)      \
    do {                             \
        free(ethp->dhost_str);       \
        free(ethp->shost_str);       \
        free(ethp->type_str);        \
        free(ethp);                  \
        ethp = NULL;                 \
    } while(0)

#define     ETHERNET_MAX_HOST_LEN       18
#define     ETHERNET_MAX_TYPEID_LEN     8

#endif      /*  __JPACKET_ETHERNET_H_ */
