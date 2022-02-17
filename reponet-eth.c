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

/*  Allocate memory for Ethernet */ 
static EthernetPtr  ethernet_init()
{
    EthernetPtr ethptr = (EthernetPtr)malloc(sizeof(Ethernet));
    memset(ethptr, 0, sizeof(Ethernet));
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

EthernetPtr ethernet_extract(const u_char *bytes)
{
    struct ether_header *eh;
    EthernetPtr         ethp;

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


    /*-----------------------------------------------------------------------------
     * TODO: ethp->type_str 
     *-----------------------------------------------------------------------------*/
    if (!ethp->dhost_str || !ethp->shost_str)
        ethernet_free(ethp);

    return ethp;
}