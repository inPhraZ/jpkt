/*
 * =====================================================================================
 *
 *       Filename:  packet.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef __REPONET_PACKET_H_
#define __REPONET_PACKET_H_

#include <sys/types.h>

u_int16_t ethernet_type(u_char *user, const u_char *bytes);

#endif  /*  __REPONET_PACKET_H_ */
