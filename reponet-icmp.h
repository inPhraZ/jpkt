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

#endif      /*  __REPONET_ICMP_H_ */
