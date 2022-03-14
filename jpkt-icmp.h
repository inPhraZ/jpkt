/*
 * =====================================================================================
 *
 *       Filename:  jpkt-icmp.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef     __JPACKET_ICMP_H_
#define     __JPACKET_ICMP_H_   1

#define     ICMPSUMLEN  7

typedef struct __jpkt_icmp {
    uint8_t type;
    uint8_t code;
    char    *type_str;
    char    *code_str;
    char    checksum[ICMPSUMLEN];
} icmp_t;

/* Allocate memory for icmp header and extract fields from bytes */
icmp_t  *icmp_extract(const u_char *bytes);

/*  Free allocated memory and assign NULL to icmpptr */
#define icmp_free(icmpptr)  \
    do {                    \
        free(icmpptr->type_str);\
        free(icmpptr->code_str);\
        free(icmpptr);      \
        icmpptr = NULL;     \
    } while(0)

#endif      /*  __JPACKET_ICMP_H_ */
