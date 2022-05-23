/*
 * =====================================================================================
 *
 *       Filename:  jpkt-udp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "jpkt-udp.h"

static udp_t *udp_alloc()
{
	udp_t *udp;
	udp = (udp_t *)malloc(sizeof(udp_t));
	if (!udp)
		return NULL;
	memset(udp, 0, sizeof(udp_t));
	return udp;
}

udp_t *udp_extract(const u_char *bytes)
{
	udp_t *udp;
	struct udphdr *udp_header;

	if (!bytes)
		return NULL;

	udp = udp_alloc();
	if (!udp)
		return NULL;

	udp_header = (struct udphdr *)bytes;

	udp->uh_sport = ntohs(udp_header->uh_sport);
	udp->uh_dport = ntohs(udp_header->uh_dport);
	udp->uh_ulen = ntohs(udp_header->uh_ulen);

	snprintf(udp->uh_sum, UDPSUMLEN,
			"0x%04x", ntohs(udp_header->uh_sum));

	return udp;
}
