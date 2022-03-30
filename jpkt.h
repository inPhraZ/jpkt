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

typedef void (*jpkt_handler)(void *, const char *, const size_t);

int jpkt_sniff(const char *iface,
		unsigned int count,
		jpkt_handler,
		void *user);

#endif		/*  __JPACKET_H_ */
