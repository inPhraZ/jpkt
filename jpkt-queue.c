/*
 * =====================================================================================
 *
 *       Filename:  jpkt-queue.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>

#include "jpkt-queue.h"

jpkt_queue	*packet_init_queue()
{
	jpkt_queue *packets = NULL;
	packets = (jpkt_queue *)malloc(sizeof(jpkt_queue));
	if (!packets)
		return NULL;

	STAILQ_INIT(packets);
	return packets;
}

void 	packet_enqueue(jpkt_queue *packets, packet_t *pkt)
{
	if (!packets || !pkt)
		return;

	STAILQ_INSERT_TAIL(packets, pkt, entries);
}

packet_t *packet_dequeue(jpkt_queue *packets)
{
	packet_t *pkt;

	if (!packets)
		return NULL;

	pkt = STAILQ_FIRST(packets);
	STAILQ_REMOVE_HEAD(packets, entries);
	return pkt;
}

void 	__packet_free_queue(jpkt_queue *packets)
{
	packet_t *p1;
	packet_t *p2;

	if (!packets)
		return;

	p1 = STAILQ_FIRST(packets);
	while (p1 != NULL) {
		p2 = STAILQ_NEXT(p1, entries);
		packet_free(p1);
		p1 = p2;
	}
	STAILQ_INIT(packets);
}
