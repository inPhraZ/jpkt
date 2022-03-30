/*
 * =====================================================================================
 *
 *       Filename:  jpkt.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

#include "jpkt.h"
#include "jpkt-packet.h"

static void jpkt_sniff_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	jpkt_handler callback = (jpkt_handler)user;
	packet_t *pktptr = packet_extract(h, bytes);
	callback(NULL, pktptr->pktmsg, pktptr->len);
	packet_free(pktptr);
}

int jpkt_sniff(const char *iface,
		unsigned int count,
		jpkt_handler callback,
		void *user)
{
	pcap_t *p = NULL;
	int to_ms;
	char errbuf[PCAP_ERRBUF_SIZE];

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	p = pcap_create(iface, errbuf);
	if (!p) {
		fprintf(stderr, "pcap_create: %s\n", errbuf);
		return 1;
	}

	to_ms = 2000;
	pcap_set_timeout(p, to_ms);
	if (pcap_activate(p)) {
		pcap_perror(p, "pcap_activate");
		pcap_close(p);
	}

	pcap_loop(p, 0, jpkt_sniff_handler, (u_char *)callback);
	pcap_close(p);

	return 0;
}
