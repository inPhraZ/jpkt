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

Packetptr allocate_packet()
{
    Packetptr pktptr;
    pktptr = (Packetptr)malloc(sizeof(Packet));
    if (!pktptr)
        return NULL;
    memset(pktptr, 0, sizeof(Packet));
    return pktptr;
}

static int  analyze_packet_eth(JsonBuilder *builder, const u_char *bytes)
{
    EthernetPtr ethp = ethernet_extract(bytes);
    if (!ethp) {
        fprintf(stderr, "ethernet_extract failed");
        return -1;
    }

    json_builder_set_member_name(builder, "eth");   /*  eth object */
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

    ethernet_free(ethp);

    json_builder_end_object(builder);   /*  end of eth object */

    return 0;
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

    json_builder_begin_object(builder); /*  main object */
    json_builder_set_member_name(builder, "layers");
    json_builder_begin_object(builder); /*  layers object */

    /*  ethernet header */
    if (analyze_packet_eth(builder, bytes) == -1) {
        free_packet(pktptr);
        json_builder_reset(builder);
        return NULL;
    }

    /*-----------------------------------------------------------------------------
     * TODO: analyze the packet
     *-----------------------------------------------------------------------------*/

    json_builder_end_object(builder);   /*  end of layers object */
    json_builder_end_object(builder);   /*  end of main object */

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
