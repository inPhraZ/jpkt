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
#include <net/ethernet.h>
#include <pcap/pcap.h>

#include "jpkt-packet.h"

void callback(u_char *user, const struct pcap_pkthdr *h,
        const u_char *bytes)
{
    packet_t *pktptr = analyze_packet(h, bytes);
    /*-----------------------------------------------------------------------------
     * TODO: add to queue
     *-----------------------------------------------------------------------------*/
    packet_free(pktptr);
}

int main()
{
    pcap_t *p;
    int to_ms;
    int pcap_status;
    char ifname[IF_NAMESIZE];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_status = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (pcap_status == -1) {
        fprintf(stderr, "pcap_init: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    pcap_if_t *alldevsp = NULL;
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_init: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (alldevsp == NULL) {
        fprintf(stderr, "No devices were found\n");
        exit(EXIT_SUCCESS);
    }

    strncpy(ifname, alldevsp->name, IF_NAMESIZE);
    pcap_freealldevs(alldevsp);

    printf("Activating %s\n", ifname);
    p = pcap_create(ifname, errbuf);
    if (p == NULL) {
        fprintf(stderr, "pcap_create: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    to_ms = 2000;
    pcap_set_timeout(p, to_ms);

    pcap_status = pcap_activate(p);
    if (pcap_status != 0) {
        pcap_perror(p, "pcap_activate");
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    pcap_loop(p, 0, callback, NULL);

    pcap_close(p);

    return 0;
}
