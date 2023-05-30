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

#include "jpkt.h"
#include "jpkt-packet.h"

struct callback_data {
	void 		 *user;
	jpkt_handler callback;
};

int jpkt_findalldevs(jpkt_if_t **alldevsp, char *errbuf)
{
	if(pcap_findalldevs(alldevsp, errbuf))
		return 1;
	return 0;
}

void jpkt_freealldevs(jpkt_if_t *alldevs)
{
	pcap_freealldevs(alldevs);
}

static void jpkt_sniff_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	struct callback_data *data = (struct callback_data *)user;
	packet_t *pktptr = packet_extract(h, bytes);
	data->callback(data->user, pktptr->pktmsg, pktptr->len);
	packet_free(pktptr);
}

int jpkt_sniff(const char *iface,
		unsigned int count,
		jpkt_handler callback,
		void *user)
{
	pcap_t *p = NULL;
	int to_ms;
	char errbuf[JPKT_ERRBUF_SIZE];

	memset(errbuf, 0, JPKT_ERRBUF_SIZE);
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
		return 1;
	}

	struct callback_data *data = NULL;
	data = (struct callback_data *)malloc(sizeof(struct callback_data));

	data->user = user;
	data->callback = callback;
	pcap_loop(p, 0, jpkt_sniff_handler, (u_char *)data);
	pcap_close(p);
	free(data);
	data = NULL;

	return 0;
}
