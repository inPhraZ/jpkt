/*
 * =====================================================================================
 *
 *       Filename:  packet.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <arpa/inet.h>
#include <net/ethernet.h>

#include "reponet-packet.h"

u_int16_t ethernet_type(u_char *user, const u_char *bytes)
{
    u_int16_t type;
    struct ether_header *ehp;

    ehp = (struct ether_header *)bytes;
    type = ntohs(ehp->ether_type);
    return type;
}
