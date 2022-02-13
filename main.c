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
#include <assert.h>
#include <net/if.h>
#include <pcap/pcap.h>

int main()
{
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
    printf("Activating %s\n", ifname);

    pcap_freealldevs(alldevsp);
    
    return 0;
}
