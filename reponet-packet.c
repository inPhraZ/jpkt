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

static int (*analyze_protocols[])(const u_char *bytes) = {
    [ETHERTYPE_PUP]         NULL,
    [ETHERTYPE_SPRITE]      NULL,
    [ETHERTYPE_IP]          NULL,
    [ETHERTYPE_ARP]         NULL,
    [ETHERTYPE_REVARP]      NULL,
    [ETHERTYPE_AT]          NULL,
    [ETHERTYPE_AARP]        NULL,
    [ETHERTYPE_VLAN]        NULL,
    [ETHERTYPE_IPX]         NULL,
    [ETHERTYPE_IPV6]        NULL,
    [ETHERTYPE_LOOPBACK]    NULL
};

Packetptr allocate_packet()
{
    Packetptr pktptr;
    pktptr = (Packetptr)malloc(sizeof(Packet));
    if (!pktptr)
        return NULL;
    memset(pktptr, 0, sizeof(Packet));
    return pktptr;
}

static uint16_t  analyze_packet_eth(JsonBuilder *builder, const u_char *bytes)
{
    uint16_t type;
    EthernetPtr ethp = ethernet_extract(bytes);
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

    type = ethp->type;
    ethernet_free(ethp);

    json_builder_end_object(builder);   /*  end of object: eth */

    return type;
}

Packetptr   analyze_packet(const struct pcap_pkthdr *h, const u_char *bytes)
{
    Packetptr pktptr;
    pktptr = allocate_packet();
    if (!pktptr) {
        perror("allocate_packet");
        return NULL;
    }

    g_autoptr(JsonBuilder) builder = json_builder_new();

    json_builder_begin_object(builder); /*  begin object: main */
    json_builder_set_member_name(builder, "layers");
    json_builder_begin_object(builder); /*  begin object: layers */

    /*  ethernet header */
    uint16_t type = analyze_packet_eth(builder, bytes);
    if (type == 0) {
        free_packet(pktptr);
        json_builder_reset(builder);
        return NULL;
    }

    /* Skip ethernet header */
    u_char *tmp_bytes = (u_char *)(bytes + sizeof(struct ether_header));

    analyze_protocols[type](tmp_bytes);

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
