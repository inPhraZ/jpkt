/*
 * =====================================================================================
 *
 *       Filename:  jpkt-udp.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef 	__JPACKET_UDP_H_
#define 	__JPACKET_UDP_H_

#include <netinet/udp.h>

#define 	UDPSUMLEN	7

typedef struct __jpkt_udp {
	uint16_t uh_sport;
	uint16_t uh_dport;
	uint16_t uh_ulen;
	char 	 uh_sum[UDPSUMLEN];
} udp_t;

udp_t *udp_extract(const u_char *bytes);

#endif		/*  __JPACKET_UDP_H_  */
