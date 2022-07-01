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

/*
     0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |                                   |
    |          data octets              |
    +-----------------------------------+
*/

/*  User Datagram format (RFC 768) */
typedef struct __jpkt_udp {
	uint16_t uh_sport;
	uint16_t uh_dport;
	uint16_t uh_ulen;
	char 	 uh_sum[UDPSUMLEN];
} udp_t;

udp_t *udp_extract(const u_char *bytes);

#define udp_free(udpptr)	\
	do { free(udpptr); udpptr = NULL; } while(0)

#endif		/*  __JPACKET_UDP_H_  */
