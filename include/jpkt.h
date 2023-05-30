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

#include "jpkt-types.h"

typedef void (*jpkt_handler)(void *user, const char *pkt, const size_t len);

int jpkt_findalldevs(jpkt_if_t **alldevsp, char *errbuf);

void jpkt_freealldevs(jpkt_if_t *alldevs);

int jpkt_sniff(const char *iface,
		unsigned int count,
		jpkt_handler,
		void *user);

#endif		/*  __JPACKET_H_ */
