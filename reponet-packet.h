/*
 * =====================================================================================
 *
 *       Filename:  packet.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef __REPONET_PACKET_H_
#define __REPONET_PACKET_H_     1

#include <sys/types.h>
#include <sys/queue.h>

/* Structure containing captured packet */
struct reponet_packet {
    size_t  len;            /*  Length of message */
    char    *pktmsg;        /* Packet info as JSON */
    STAILQ_ENTRY(reponet_packet)   entries;
};

STAILQ_HEAD(packet_queue, reponet_packet);

u_int16_t ethernet_type(u_char *user, const u_char *bytes);

#endif  /*  __REPONET_PACKET_H_ */
