/*
 * =====================================================================================
 *
 *       Filename:  jpkt-queue.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef 	__JPACKET_QUEUE_H_
#define 	__JPACKET_QUEUE_H_	1

#include <sys/queue.h>

#include "jpkt-packet.h"

/* Singly-linked Tail queue decleration for packet queue */
STAILQ_HEAD(__packet_queue, __jpkt_packet);
typedef struct __packet_queue jpkt_queue;

/* initialize new queue */
jpkt_queue	*packet_init_queue();

/* insert pkt at tail of packets queue */
void 		 packet_enqueue(jpkt_queue *packets, const packet_t *pkt);

/* remove head from packets queue  */
packet_t	*packet_dequeue(jpkt_queue *packets);

/* free packets queue */
void 		__packet_free_queue(jpkt_queue *packets);

/* free packets queue and assign NULL to pointer */
#define 	packet_free_queue(packets)	\
	do { __packet_free_queue(packets); packets = NULL; } while(0)

#endif 		/*  __JPACKET_QUEUE_H_ */
