/*
 * =====================================================================================
 *
 *       Filename:  packet.c
 *         Author:  Farzin 
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <glib-object.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <json-glib/json-glib.h>

#include "jpkt-packet.h"
#include "jpkt-eth.h"
#include "jpkt-arp.h"
#include "jpkt-ip.h"

/*  prototypes for packet routines */
static uint16_t packet_eth(JsonBuilder *builder, const u_char *bytes);
static int      packet_arp(JsonBuilder *builder, const u_char *bytes);
static int      packet_ip(JsonBuilder *builder, const u_char *bytes);

/*  dummy function for protocols that have not yet been supported */
static int packet_dummy(JsonBuilder *builder, const u_char *bytes)
{
    return 0;
}

#if 0
/*  ETHERTYPE_* has missing numbers.
 *  invalid ethertype protocol can crash the program */

/*  function pointers to analyze ethertype protocols
 *  <net/ethernet.h>
 */
static int (*ethertype_protocols[])(JsonBuilder *builder,
        const u_char *bytes) = {
    [ETHERTYPE_PUP]         packet_dummy,
    [ETHERTYPE_SPRITE]      packet_dummy,
    [ETHERTYPE_IP]          packet_ip,
    [ETHERTYPE_ARP]         packet_arp,
    [ETHERTYPE_REVARP]      packet_dummy,
    [ETHERTYPE_AT]          packet_dummy,
    [ETHERTYPE_AARP]        packet_dummy,
    [ETHERTYPE_VLAN]        packet_dummy,
    [ETHERTYPE_IPX]         packet_dummy,
    [ETHERTYPE_IPV6]        packet_dummy,
    [ETHERTYPE_LOOPBACK]    packet_dummy
};
#endif

static packet_t *packet_alloc()
{
    packet_t *pktptr;
    pktptr = (packet_t *)malloc(sizeof(packet_t));
    if (!pktptr)
        return NULL;
    memset(pktptr, 0, sizeof(packet_t));
    return pktptr;
}

/*  timestamp of captured packet */
static void packet_timestamp(JsonBuilder *builder,
		const struct pcap_pkthdr *h)
{
	if (!builder || !h)
		return;

	/*  timestamp */
	json_builder_set_member_name(builder, "timestamp");	/*  begin object: timestamp */
	json_builder_begin_object(builder);

	/*  ts.sec */
	json_builder_set_member_name(builder, "ts.sec");
	json_builder_add_int_value(builder, h->ts.tv_sec);

	/*  ts.usec */
	json_builder_set_member_name(builder, "ts.usec");
	json_builder_add_int_value(builder, h->ts.tv_usec);

	json_builder_end_object(builder);	/*  end of object */
}

/*  Analyze raw bytes of traffic and  */
packet_t   *analyze_packet(const struct pcap_pkthdr *h, const u_char *bytes)
{
    packet_t *pktptr;
    pktptr = packet_alloc();
    if (!pktptr) {
        perror("allocate_packet");
        return NULL;
    }

    g_autoptr(JsonBuilder) builder = json_builder_new();

    json_builder_begin_object(builder); /*  begin object: main */

	/*  timestamp */
	packet_timestamp(builder, h);

    json_builder_set_member_name(builder, "layers");
    json_builder_begin_object(builder); /*  begin object: layers */

    /*  ethernet header */
    uint16_t type = packet_eth(builder, bytes);
    if (type == 0) {
        packet_free(pktptr);
        json_builder_reset(builder);
        return NULL;
    }

    /* Skip ethernet header */
    u_char *tmp_bytes = (u_char *)(bytes + sizeof(struct ether_header));

	switch(type) {
		case ETHERTYPE_IP:
			packet_ip(builder, tmp_bytes);
			break;
		case ETHERTYPE_ARP:
			packet_arp(builder, tmp_bytes);
			break;
		default:
			break;
	}
#if 0
    ethertype_protocols[type](builder, tmp_bytes);
#endif

    /*-----------------------------------------------------------------------------
     * TODO: analyze the packet
     *-----------------------------------------------------------------------------*/

    json_builder_end_object(builder);   /*  end of object: layers */
    json_builder_end_object(builder);   /*  end of object: main */

    g_autoptr(JsonNode) root = json_builder_get_root(builder);
    g_autoptr(JsonGenerator) gen = json_generator_new();

    json_generator_set_root(gen, root);
    pktptr->pktmsg = json_generator_to_data(gen, NULL);
    g_autofree char *tmp = json_generator_to_data(gen, NULL);
    size_t tlen = strlen(tmp);
    pktptr->pktmsg = (char *)malloc(tlen+1);
    memset(pktptr->pktmsg, 0, tlen+1);
    memmove(pktptr->pktmsg, tmp, tlen);
    printf("%s\n", pktptr->pktmsg);

    return pktptr;
}

static uint16_t  packet_eth(JsonBuilder *builder, const u_char *bytes)
{
    uint16_t type;
    ethernet_t *ethp = ethernet_extract(bytes);
    if (!ethp) {
        fprintf(stderr, "ethernet_extract failed");
        return 0;
    }

    json_builder_set_member_name(builder, "eth");   /*  begin object: eth */
    json_builder_begin_object(builder);

    /* eth.shost  */
    json_builder_set_member_name(builder, "eth.shost");
    json_builder_add_string_value(builder, ethp->shost_str);

    /* eth.dhost  */
    json_builder_set_member_name(builder, "eth.dhost");
    json_builder_add_string_value(builder, ethp->dhost_str);

    /* eth.type */
    json_builder_set_member_name(builder, "eth.type");
    json_builder_add_string_value(builder, ethp->type_str);

    json_builder_end_object(builder);   /*  end of object: eth */

    type = ethp->type;
    ethernet_free(ethp);

    return type;
}

static int  packet_arp(JsonBuilder *builder, const u_char *bytes)
{
    arp_t *arpptr = arp_extract(bytes);
    if (!arpptr)
        return 1;

    json_builder_set_member_name(builder, "arp");   /*  begin object: arp */
    json_builder_begin_object(builder);

    /* arp.hw.type  */
    json_builder_set_member_name(builder, "arp.hw.type");
    json_builder_add_string_value(builder, arpptr->ar_hrd);

    /* arp.proto.type  */
    json_builder_set_member_name(builder, "arp.proto.type");
    json_builder_add_string_value(builder, arpptr->ar_pro);

    /* arp.hw.size */
    json_builder_set_member_name(builder, "arp.hw.size");
    json_builder_add_int_value(builder, arpptr->ar_hln);

    /* arp.proto.size */
    json_builder_set_member_name(builder, "arp.proto.size");
    json_builder_add_int_value(builder, arpptr->ar_pln);

    /*  arp.opcode */
    json_builder_set_member_name(builder, "arp.opcode");
    json_builder_add_string_value(builder, arpptr->ar_op);

    /*  arp.src.mac */
    json_builder_set_member_name(builder, "arp.src.mac");
    json_builder_add_string_value(builder, arpptr->ar_sha);

    /*  arp.src.ip */
    json_builder_set_member_name(builder, "arp.src.ip");
    json_builder_add_string_value(builder, arpptr->ar_sip);

    /*  arp.dst.mac */
    json_builder_set_member_name(builder, "arp.dst.mac");
    json_builder_add_string_value(builder, arpptr->ar_tha);

    /*  arp.dst.ip */
    json_builder_set_member_name(builder, "arp.dst.ip");
    json_builder_add_string_value(builder, arpptr->ar_tip);

    json_builder_end_object(builder);   /*  end of object: arp */

    arp_free(arpptr);

    return 0;
}

/*  analyze raw bytes to extract ip header */
static int packet_ip(JsonBuilder *builder, const u_char *bytes)
{
    uint8_t ip_p;
	uint16_t len;

    ip_t *ipptr;
    if (!builder || !bytes)
        return 1;

    ipptr = ip_extract(bytes);

    json_builder_set_member_name(builder, "ip");    /*  begin object: ip */
    json_builder_begin_object(builder);

    /* ip.version  */
    json_builder_set_member_name(builder, "ip.version");
    json_builder_add_int_value(builder, ipptr->ip_v);

    /* ip.hdrlen  */
    json_builder_set_member_name(builder, "ip.hdrlen");
    json_builder_add_int_value(builder, ipptr->ip_hl);

    /* ip.tos  */
    json_builder_set_member_name(builder, "ip.tos");
    json_builder_add_string_value(builder, ipptr->ip_tos);

    /* ip.len  */
    json_builder_set_member_name(builder, "ip.len");
    json_builder_add_int_value(builder, ipptr->ip_len);

    /* ip.id  */
    json_builder_set_member_name(builder, "ip.id");
    json_builder_add_string_value(builder, ipptr->ip_id);

    /* ip.flags  */
    json_builder_set_member_name(builder, "ip.flags");
    json_builder_add_string_value(builder, ipptr->ip_flags);

    /* ip.off  */
    json_builder_set_member_name(builder, "ip.off");
    json_builder_add_string_value(builder, ipptr->ip_off);

    /* ip.ttl  */
    json_builder_set_member_name(builder, "ip.ttl");
    json_builder_add_int_value(builder, ipptr->ip_ttl);

    /* ip.protocol */
    json_builder_set_member_name(builder, "ip.protocol");
    json_builder_add_int_value(builder, ipptr->ip_p);

    /* ip.protocol.str  */
    json_builder_set_member_name(builder, "ip.protocol.str");
    json_builder_add_string_value(builder, ipptr->ip_protocol);

    /* ip.shecksum  */
    json_builder_set_member_name(builder, "ip.checksum");
    json_builder_add_string_value(builder, ipptr->ip_sum);

    /* ip.src  */
    json_builder_set_member_name(builder, "ip.src");
    json_builder_add_string_value(builder, ipptr->ip_src);

    /* ip.dst  */
    json_builder_set_member_name(builder, "ip.dst");
    json_builder_add_string_value(builder, ipptr->ip_dst);

    json_builder_end_object(builder);               /*  end of object: ip */

    ip_p = ipptr->ip_p;
	len = ipptr->ip_len - ipptr->ip_hl;

    free(ipptr);

    ip_upper(builder, bytes, ip_p, len);
    /*-----------------------------------------------------------------------------
     * TODO: analyze upper protocol (ip.protocol) 
     *-----------------------------------------------------------------------------*/
    return 0;
}
