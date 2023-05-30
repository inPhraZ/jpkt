/*
 * =====================================================================================
 *
 *       Filename:  jpkt-types.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef 		__JPACKET_TYPES_H_
#define 		__JPACKET_TYPES_H_  1

#include <net/if.h>
#include <pcap/pcap.h>

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE    256
#endif

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#define JPKT_ERRBUF_SIZE    PCAP_ERRBUF_SIZE
#define JPKT_IF_NAMESIZE    IF_NAMESIZE

typedef pcap_if_t jpkt_if_t;

#endif		/*  __JPACKET_TYPES_H_ */