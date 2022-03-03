/*
 * =====================================================================================
 *
 *       Filename:  reponet-eth.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#include "reponet-eth.h"

/*  string of Ethernet protocol ID's */
static char *ethernet_type_ids[] = {
    [ETHERTYPE_PUP]         "IP",
    [ETHERTYPE_SPRITE]      "SPRITE",
    [ETHERTYPE_IP]          "IPv4",
    [ETHERTYPE_ARP]         "ARP",
    [ETHERTYPE_REVARP]      "REVARP",
    [ETHERTYPE_AT]          "AT",
    [ETHERTYPE_AARP]        "AARP",
    [ETHERTYPE_VLAN]        "VLAN",
    [ETHERTYPE_IPX]         "IPX",
    [ETHERTYPE_IPV6]        "IPv6",
    [ETHERTYPE_LOOPBACK]    "LOOPBACK"
};

/*  Allocate memory for Ethernet */ 
static ethernet_t  *ethernet_init()
{
    ethernet_t *ethptr = (ethernet_t *)malloc(sizeof(ethernet_t));
    memset(ethptr, 0, sizeof(ethernet_t));
    return ethptr;
}

static char *ethernet_get_shost(struct ether_header *eh)
{
    char *tmp;
    char *host;

    if (!eh)
        return NULL;

    tmp = ether_ntoa((struct ether_addr *)eh->ether_shost);
    host = strndup(tmp, ETHERNET_MAX_HOST_LEN);
    return host;
}

static char *ethernet_get_type(const uint16_t type)
{
    char *type_str;
    type_str = strndup(ethernet_type_ids[type], ETHERNET_MAX_TYPEID_LEN);
    return type_str;
}

static char *ethernet_get_dhost(struct ether_header *eh)
{
    char *tmp;
    char *host;

    if (!eh)
        return NULL;

    tmp = ether_ntoa((struct ether_addr *)eh->ether_dhost);
    host = strndup(tmp, ETHERNET_MAX_HOST_LEN);
    return host;
}

ethernet_t *ethernet_extract(const u_char *bytes)
{
    struct ether_header *eh;
    ethernet_t          *ethp;

    if (!bytes)
        return NULL;

    ethp = ethernet_init();
    if (!ethp) {
        perror("allocate Ethernet");
        return NULL;
    }

    eh = (struct ether_header *)bytes;
    ethp->type = ntohs(eh->ether_type);

    ethp->dhost_str = ethernet_get_dhost(eh);
    ethp->shost_str = ethernet_get_shost(eh);
    ethp->type_str  = ethernet_get_type(ethp->type);

    if (!ethp->dhost_str
            || !ethp->shost_str
            || !ethp->type_str)
        ethernet_free(ethp);

    return ethp;
}
