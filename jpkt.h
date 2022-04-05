/*
 * =====================================================================================
 *
 *       Filename:  jpkt.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef 		__JPACKET_H_
#define 		__JPACKET_H_	1

typedef pcap_if_t jpkt_if_t;

typedef void (*jpkt_handler)(void *, const char *, const size_t);

int jpkt_findalldevs(jpkt_if_t **alldevsp, char *errbuf);

int jpkt_sniff(const char *iface,
		unsigned int count,
		jpkt_handler,
		void *user);

#endif		/*  __JPACKET_H_ */
