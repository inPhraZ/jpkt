/*
 * =====================================================================================
 *
 *       Filename:  jpkt-data.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef 	__JPACKET_DATA_H_
#define 	__JPACKET_DATA_H_	1

#include <json-glib/json-glib.h>

uint16_t data_as_json_object(JsonBuilder *builder,
		const u_char *bytes, const uint16_t slen);

char *data_to_string(const u_char *bytes,
		const uint16_t slen, uint16_t *dlen);

#endif		/*  __JPACKET_DATA_H_  */
