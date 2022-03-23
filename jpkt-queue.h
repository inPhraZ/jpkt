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


#endif 		/*  __JPACKET_QUEUE_H_ */
