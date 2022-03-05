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

#include "reponet-packet.h"
#include "reponet-eth.h"
#include "reponet-ip.h"

/*  prototypes for packet routines */
static uint16_t packet_eth(JsonBuilder *builder, const u_char *bytes);
static int      packet_ip(JsonBuilder *builder, const u_char *bytes);

/*  dummy function for protocols that have not yet been supported */
static int dummy_call(JsonBuilder *builder, const u_char *bytes)
{
    return 0;
}

/*  function pointers to analyze ethertype protocols
 *  <net/ethernet.h>
 */
static int (*ethertype_protocols[])(JsonBuilder *builder,
        const u_char *bytes) = {
    [ETHERTYPE_PUP]         dummy_call,
    [ETHERTYPE_SPRITE]      dummy_call,
    [ETHERTYPE_IP]          packet_ip,
    [ETHERTYPE_ARP]         dummy_call,
    [ETHERTYPE_REVARP]      dummy_call,
    [ETHERTYPE_AT]          dummy_call,
    [ETHERTYPE_AARP]        dummy_call,
    [ETHERTYPE_VLAN]        dummy_call,
    [ETHERTYPE_IPX]         dummy_call,
    [ETHERTYPE_IPV6]        dummy_call,
    [ETHERTYPE_LOOPBACK]    dummy_call
};

static packet_t *packet_alloc()
{
    packet_t *pktptr;
    pktptr = (packet_t *)malloc(sizeof(packet_t));
    if (!pktptr)
        return NULL;
    memset(pktptr, 0, sizeof(packet_t));
    return pktptr;
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

    ethertype_protocols[type](builder, tmp_bytes);

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

/*  analyze raw bytes to extract ip header */
static int packet_ip(JsonBuilder *builder, const u_char *bytes)
{
    ip_t *ipptr;
    if (!builder || !bytes)
        return 1;

    ipptr = ip_extract(bytes);

    json_builder_set_member_name(builder, "ip");    /*  begin object: ip */
    json_builder_begin_object(builder);

    /* ip.version  */
    json_builder_set_member_name(builder, "ip.version");
    json_builder_add_string_value(builder, ipptr->version);

    /* ip.hdrlen  */
    json_builder_set_member_name(builder, "ip.hdrlen");
    json_builder_add_string_value(builder, ipptr->hlen);

    /* ip.tos  */
    json_builder_set_member_name(builder, "ip.tos");
    json_builder_add_string_value(builder, ipptr->tos);

    /* ip.len  */
    json_builder_set_member_name(builder, "ip.len");
    json_builder_add_string_value(builder, ipptr->tlen);

    /* ip.id  */
    json_builder_set_member_name(builder, "ip.id");
    json_builder_add_string_value(builder, ipptr->id);

    /* ip.flags  */
    json_builder_set_member_name(builder, "ip.flags");
    json_builder_add_string_value(builder, ipptr->flags);

    /* ip.off  */
    json_builder_set_member_name(builder, "ip.off");
    json_builder_add_string_value(builder, ipptr->off);

    /* ip.ttl  */
    json_builder_set_member_name(builder, "ip.ttl");
    json_builder_add_string_value(builder, ipptr->ttl);

    /* ip.protocol  */
    json_builder_set_member_name(builder, "ip.protocol");
    json_builder_add_string_value(builder, ipptr->protocol);

    /* ip.shecksum  */
    json_builder_set_member_name(builder, "ip.checksum");
    json_builder_add_string_value(builder, ipptr->checksum);

    /* ip.src  */
    json_builder_set_member_name(builder, "ip.src");
    json_builder_add_string_value(builder, ipptr->saddr);

    /* ip.dst  */
    json_builder_set_member_name(builder, "ip.dst");
    json_builder_add_string_value(builder, ipptr->daddr);

    json_builder_end_object(builder);               /*  end of object: ip */

    free(ipptr);

    /*-----------------------------------------------------------------------------
     * TODO: analyze upper protocol (ip.protocol) 
     *-----------------------------------------------------------------------------*/
    return 0;
}
