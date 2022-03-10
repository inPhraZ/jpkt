/*
 * =====================================================================================
 *
 *       Filename:  reponet-icmp.h
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#ifndef     __REPONET_ICMP_H_
#define     __REPONET_ICMP_H_   1

#define     ICMPSUMLEN  7

typedef struct __reponet_icmp {
    char    *type;
    char    *code;
    char    checksum[ICMPSUMLEN];
} icmp_t;

/* Allocate memory for icmp header and extract fields from bytes */
icmp_t  *icmp_extract(const u_char *bytes);

/*  Free allocated memory and assign NULL to icmpptr */
#define icmp_free(icmpptr)  \
    do {                    \
        free(icmpptr->type);\
        free(icmpptr->code);\
        free(icmpptr);      \
        icmpptr = NULL;     \
    } while(0)

#endif      /*  __REPONET_ICMP_H_ */
