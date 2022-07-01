/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *         Author:  Farzin
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "jpkt.h"

void callback(void *user, const char *pkt, const size_t len)
{
	printf("%ld\n%s\n", len, pkt);
}

int main()
{
    char ifname[IF_NAMESIZE + 1];
    char errbuf[PCAP_ERRBUF_SIZE];

    jpkt_if_t *alldevsp = NULL;
    if (jpkt_findalldevs(&alldevsp, errbuf)) {
        fprintf(stderr, "pcap_init: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (alldevsp == NULL) {
        fprintf(stderr, "No devices were found\n");
        exit(EXIT_SUCCESS);
    }

	jpkt_if_t *tmp = alldevsp;
	while(tmp) {
		printf("%s\n", tmp->name);
		tmp = tmp->next;
	}
	memset(ifname, 0, IF_NAMESIZE + 1);
    strncpy(ifname, alldevsp->name, IF_NAMESIZE);
    jpkt_freealldevs(alldevsp);

	int a = 10;
	jpkt_sniff(ifname, 0, callback, &a);

    return 0;
}
