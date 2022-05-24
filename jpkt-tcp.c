/*
 * =====================================================================================
 *
 *       Filename:  jpkt-tcp.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "jpkt-tcp.h"

static tcp_t *tcp_alloc()
{
	tcp_t *tcp = NULL;
	tcp = (tcp_t *)malloc(sizeof(tcp_t));
	if (!tcp)
		return NULL;
	memset(tcp, 0, sizeof(tcp_t));
	return tcp;
}

tcp_t	*tcp_extract(const u_char *bytes)
{
	if (!bytes)
		return NULL;

	tcp_t *tcp;
	struct tcphdr *tcp_header;
	uint16_t tmp = 0x0000;

	tcp_header = (struct tcphdr *)bytes;

	tcp->th_sport = ntohs(tcp_header->th_sport);
	tcp->th_dport = ntohs(tcp_header->th_dport);
	tcp->th_seq = ntohl(tcp_header->th_seq);
	tcp->th_ack = ntohl(tcp_header->th_ack);
	tcp->th_doff = tcp_header->doff;
	tmp = (tcp_header->th_x2 << 6) | tcp_header->th_flags;
	tcp->th_wnd = ntohs(tcp_header->th_win);
	tcp->th_urp = ntohs(tcp_header->th_urp);

	snprintf(tcp->th_flags, TCPFLGLEN,
			"0x%03x", tmp);

	snprintf(tcp->th_sum, TCPSUMLEN,
			"0x%04x", ntohs(tcp_header->th_sum));

	return tcp;
}
