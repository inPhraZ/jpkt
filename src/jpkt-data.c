/*
 * =====================================================================================
 *
 *       Filename:  jpkt-data.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "jpkt-data.h"

char *data_to_string(const u_char *bytes,
		const uint16_t slen, uint16_t *dlen)
{
	uint16_t len;
	char tmp[4];
	char *bstr = NULL;

	if (!bytes || !dlen)
		return NULL;

	len = (slen * 2) + (slen - 1);
	*dlen = len;

	bstr = (char *)malloc(len + 1);
	if (!bstr)
		return NULL;
	memset(bstr, 0, len + 1);
	memset(tmp, 0, 4);

	uint16_t i;
	for (i = 0; i < slen - 1; ++i) {
		snprintf(tmp, 4, "%02x:", bytes[i]);
		strncat(bstr, tmp, 4);
	}
	/*  last byte */
	sprintf(tmp, "%02x", bytes[i]);
	strncat(bstr, tmp, 4);

	return bstr;
}

uint16_t data_as_json_object(JsonBuilder *builder,
		const u_char *bytes, const uint16_t slen)
{
	uint16_t dlen;
	char *bstr;
	
	if (!builder || !bytes)
		return 0;

	bstr = data_to_string(bytes, slen, &dlen);
	if (!bstr)
		return 0;

	/*  data */
	json_builder_set_member_name(builder, "data");	/*  begin object: data  */
	json_builder_begin_object(builder);

	/*  data.data */
	json_builder_set_member_name(builder, "data.data");
	json_builder_add_string_value(builder, bstr);

	/*  data.len */
	json_builder_set_member_name(builder, "data.len");
	json_builder_add_int_value(builder, slen);

	json_builder_end_object(builder);	/*  end of object: data  */

	free(bstr);

	return dlen;
}
