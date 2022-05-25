/*
 * =====================================================================================
 *
 *       Filename:  jpkt-ip.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "jpkt-ip.h"
#include "jpkt-icmp.h"
#include "jpkt-udp.h"
#include "jpkt-tcp.h"
#include "jpkt-data.h"

static int ip_icmp(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len);

static int ip_udp(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len);

static int ip_tcp(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len);

/*  dummy finction for protocols that have not yet been supported */
static int ip_dummy(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len)
{
    return 0;
}

/* IP protocol numbers */
static const char *ip_protocol_nums[] = {
    [IPPROTO_IP]        "IP",
    [IPPROTO_ICMP]      "ICMP",
    [IPPROTO_IGMP]      "IGMP",
    [IPPROTO_IPIP]      "IPIP",
    [IPPROTO_TCP]       "TCP",
    [IPPROTO_EGP]       "EGP",
    [IPPROTO_PUP]       "PUP",
    [IPPROTO_UDP]       "UDP",
    [IPPROTO_IDP]       "IDP",
    [IPPROTO_TP]        "TP",
    [IPPROTO_DCCP]      "DCCP",
    [IPPROTO_IPV6]      "IPv6",
    [IPPROTO_RSVP]      "RSVP",
    [IPPROTO_GRE]       "GRE",
    [IPPROTO_ESP]       "ESP",
    [IPPROTO_AH]        "AH",
    [IPPROTO_MTP]       "MTP",
    [IPPROTO_BEETPH]    "BEETPH",
    [IPPROTO_ENCAP]     "ENCAP",
    [IPPROTO_PIM]       "PIM",
    [IPPROTO_COMP]      "COMP",
    [IPPROTO_SCTP]      "SCTP",
    [IPPROTO_UDPLITE]   "UDPLITE",
    [IPPROTO_MPLS]      "MPLS",
    [IPPROTO_ETHERNET]  "ETHERNET",
    [IPPROTO_RAW]       "RAW",
    [IPPROTO_MPTCP]     "MPTCP"
};

#if 0
/* IPPROTO_* has missing numbers
 * invalid protocol types will crash the program */

/*  function pointers to analyze upper protocols */
static int (*ip_upper_protocols[])(JsonBuilder *builder,
        const u_char *bytes, const uint16_t len) = {
    [IPPROTO_IP]        ip_dummy,
    [IPPROTO_ICMP]      ip_icmp,
    [IPPROTO_IGMP]      ip_dummy,
    [IPPROTO_IPIP]      ip_dummy,
    [IPPROTO_TCP]       ip_dummy,
    [IPPROTO_EGP]       ip_dummy,
    [IPPROTO_PUP]       ip_dummy,
    [IPPROTO_UDP]       ip_dummy,
    [IPPROTO_IDP]       ip_dummy,
    [IPPROTO_TP]        ip_dummy,
    [IPPROTO_DCCP]      ip_dummy,
    [IPPROTO_IPV6]      ip_dummy,
    [IPPROTO_RSVP]      ip_dummy,
    [IPPROTO_GRE]       ip_dummy,
    [IPPROTO_ESP]       ip_dummy,
    [IPPROTO_AH]        ip_dummy,
    [IPPROTO_MTP]       ip_dummy,
    [IPPROTO_BEETPH]    ip_dummy,
    [IPPROTO_ENCAP]     ip_dummy,
    [IPPROTO_PIM]       ip_dummy,
    [IPPROTO_COMP]      ip_dummy,
    [IPPROTO_SCTP]      ip_dummy,
    [IPPROTO_UDPLITE]   ip_dummy,
    [IPPROTO_MPLS]      ip_dummy,
    [IPPROTO_ETHERNET]  ip_dummy,
    [IPPROTO_RAW]       ip_dummy,
    [IPPROTO_MPTCP]     ip_dummy
};
#endif

ip_t *ip_extract(const u_char *bytes)
{
    ip_t *ipptr;
    struct ip *ip_header;
    unsigned short fl_off;

    if (!bytes)
        return NULL;

    ipptr = (ip_t *)malloc(sizeof(ip_t));
    if (!ipptr)
        return NULL;

    memset(ipptr, 0, sizeof(ip_t));
    ip_header = (struct ip*)(bytes);

    ipptr->ip_v = ip_header->ip_v;
    ipptr->ip_hl = ip_header->ip_hl * 4;
    ipptr->ip_ttl = ip_header->ip_ttl;
    ipptr->ip_p = ip_header->ip_p;
    ipptr->ip_len = ntohs(ip_header->ip_len);

    /* 
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |Flags|    Fragment Offset      |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    fl_off = ntohs(ip_header->ip_off);
    snprintf(ipptr->ip_flags, IPFLAGLEN,
            "0x%x", (fl_off & (~IP_OFFMASK)) >> 13);
    snprintf(ipptr->ip_off, IPOFFLEN,
            "0x%x", (fl_off & IP_OFFMASK));

    snprintf(ipptr->ip_tos, IPTOSLEN,
            "0x%x", ip_header->ip_tos);
    snprintf(ipptr->ip_id, IPIDLEN,
            "0x%x", ntohs(ip_header->ip_id));
    snprintf(ipptr->ip_protocol, IPPROTOLEN,
            "%s", ip_protocol_nums[ip_header->ip_p]);
    snprintf(ipptr->ip_sum, IPSUMLEN,
            "0x%x", ntohs(ip_header->ip_sum));
    snprintf(ipptr->ip_src, IPADDRLEN,
            "%s", inet_ntoa(ip_header->ip_src));
    snprintf(ipptr->ip_dst, IPADDRLEN,
            "%s", inet_ntoa(ip_header->ip_dst));

    return ipptr;
}

int ip_upper(JsonBuilder *builder, const u_char *bytes,
        const uint8_t ip_p, const uint16_t len)
{
    u_char *pbytes;
    if (!builder || !bytes)
        return 1;

    pbytes = (u_char *)(bytes + sizeof(struct ip));

	switch(ip_p) {
		case IPPROTO_ICMP:
			ip_icmp(builder, pbytes, len);
			break;
		case IPPROTO_UDP:
			ip_udp(builder, pbytes, len);
			break;
		case IPPROTO_TCP:
			ip_tcp(builder, pbytes, len);
			break;
		default:
			ip_dummy(builder, pbytes, len);
			break;
	}

#if 0
    ip_upper_protocols[ip_p](builder, pbytes, len);
#endif

    return 0;
}

static int ip_icmp(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len)
{
	uint16_t slen;
	u_char	*dbytes;

	if (!builder || !bytes)
		return 1;

	icmp_t *icmpptr = icmp_extract(bytes);

	json_builder_set_member_name(builder, "icmp");  /*  begin object: icmp */
	json_builder_begin_object(builder);

	/*  icmp.type */
	json_builder_set_member_name(builder, "icmp.type");
	json_builder_add_int_value(builder, icmpptr->type);

	/*  icmp.code */
	json_builder_set_member_name(builder, "icmp.code");
	json_builder_add_int_value(builder, icmpptr->code);

	/*  icmp.type.str */
	json_builder_set_member_name(builder, "icmp.type.str");
	json_builder_add_string_value(builder, icmpptr->type_str);

	/*  icmp.code.str */
	json_builder_set_member_name(builder, "icmp.code.str");
	json_builder_add_string_value(builder, icmpptr->code_str);

	/*  icmp.checksum */
	json_builder_set_member_name(builder, "icmp.checksum");
	json_builder_add_string_value(builder, icmpptr->checksum);

	/*  data */
	slen = len - sizeof(struct icmphdr);
	dbytes = (u_char *)(bytes + sizeof(struct icmphdr));
	data_as_json_object(builder, dbytes, slen);

	json_builder_end_object(builder);   /*  end of object: icmp */

	icmp_free(icmpptr);

	return 0;
}

static int ip_udp(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len)
{
	udp_t *udpptr;

	if (!builder || !bytes)
		return 1;

	udpptr  = udp_extract(bytes);

	json_builder_set_member_name(builder, "udp");  /*  begin object: udp */
	json_builder_begin_object(builder);

	/*  udp.srcport */
	json_builder_set_member_name(builder, "udp.srcport");
	json_builder_add_int_value(builder, udpptr->uh_sport);

	/*  udp.dstport */
	json_builder_set_member_name(builder, "udp.dstport");
	json_builder_add_int_value(builder, udpptr->uh_dport);

	/*  udp.length */
	json_builder_set_member_name(builder, "udp.length");
	json_builder_add_int_value(builder, udpptr->uh_ulen);

	/*  udp.checksum */
	json_builder_set_member_name(builder, "udp.checksum");
	json_builder_add_string_value(builder, udpptr->uh_sum);

	/*-----------------------------------------------------------------------------
	 * TODO: Data 
	 *-----------------------------------------------------------------------------*/

	json_builder_end_object(builder);   /*  end of object: icmp */

	udp_free(udpptr);

	return 0;
}

static int ip_tcp(JsonBuilder *builder,
		const u_char *bytes, const uint16_t len)
{
	tcp_t *tcpptr;

	if (!builder || !bytes)
		return 1;

	tcpptr = tcp_extract(bytes);

	json_builder_set_member_name(builder, "tcp");  /*  begin object: tcp */
	json_builder_begin_object(builder);

	/*  tcp.sport */
	json_builder_set_member_name(builder, "tcp.sport");
	json_builder_add_int_value(builder, tcpptr->th_sport);

	/*  tcp.dport */
	json_builder_set_member_name(builder, "tcp.dport");
	json_builder_add_int_value(builder, tcpptr->th_dport);

	/*  tcp.seq */
	json_builder_set_member_name(builder, "tcp.seq");
	json_builder_add_int_value(builder, tcpptr->th_seq);

	/*  tcp.ack */
	json_builder_set_member_name(builder, "tcp.ack");
	json_builder_add_int_value(builder, tcpptr->th_ack);

	/*  tcp.doff */
	json_builder_set_member_name(builder, "tcp.doff");
	json_builder_add_int_value(builder, tcpptr->th_doff);

	/*  tcp.flags */
	json_builder_set_member_name(builder, "tcp.flags");
	json_builder_add_string_value(builder, tcpptr->th_flags);

	/*  tcp.wnd */
	json_builder_set_member_name(builder, "tcp.wnd");
	json_builder_add_int_value(builder, tcpptr->th_wnd);

	/*  tcp.urp */
	json_builder_set_member_name(builder, "tcp.urp");
	json_builder_add_int_value(builder, tcpptr->th_urp);

	/*  tcp.checksum */
	json_builder_set_member_name(builder, "tcp.checksum");
	json_builder_add_string_value(builder, tcpptr->th_sum);

	json_builder_end_object(builder);   /*  end of object: tcp */

	tcp_free(tcpptr);

	return 0;
}
