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
		strncat(bstr, tmp, 3);
	}
	/*  last byte */
	sprintf(tmp, "%02x", bytes[i]);
	strncat(bstr, tmp, 3);

	return bstr;
}
