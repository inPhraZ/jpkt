/*
 * =====================================================================================
 *
 *       Filename:  jpkt-tcp.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef 	__JPACKET_TCP_H_
#define 	__JPACKET_TCP_H_	1

#include <netinet/tcp.h>

#define 	TCPFLGLEN	6
#define 	TCPSUMLEN	7

/*

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*  TCP header format (RFC 793) */
typedef struct __jpkt_tcp {
	uint16_t 	th_sport;				/*  Source port */
	uint16_t	th_dport;				/*  Destination port */
	uint32_t	th_seq;					/*  Sequence number */
	uint32_t 	th_ack;					/*  Acknowledgement number */
	uint8_t		th_doff;				/*  Data offset */
	char 		th_flags[TCPFLGLEN];	/*  (Reserved, URG, ACK, PSH, RST, SYN, FIN) */
	uint16_t 	th_wnd;		/*  Window */
	uint16_t 	th_urp;		/*  Urgent pointer */
	char		th_sum[TCPSUMLEN];
} tcp_t;

tcp_t	*tcp_extract(const u_char *bytes);

#define tcp_free(tcpptr)	\
	do { free(tcpptr); tcpptr = NULL; } while(0)

#endif		/*  __JPACKET_TCP_H_ */
