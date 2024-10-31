#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define MAX_FRAME_LENGTH     (256 * 1024 * 1024)
typedef struct cassandra_wing_ {
    uint32_t seq;
    uint8_t  header_cnt;
} cassandra_wing_t;

typedef struct cassandra_data_ {
    cassandra_wing_t client, server;
} cassandra_data_t;

//refer cassandra 3.0.3 Transport/Frame.java
static bool is_cassandra_internode(uint8_t *ptr, uint32_t len)
{
    uint8_t * ptmp = ptr;
    int left = len > 32 ? 32: len;
    while (left > 4) {
        if (ptmp[0] == 0xCA && ptmp[1] == 0x55 && ptmp[2] == 0x2D && ptmp[3] == 0xFA) {
            return true;
        } 
        left --;
        ptmp ++;
    }
    return false;

}

#define     CO_RESPONSE    1
#define     CO_REQUEST     0
uint8_t ca_opcode[] = {
            CO_RESPONSE, 
            CO_REQUEST,  
            CO_RESPONSE, 
            CO_RESPONSE, 
            CO_REQUEST,  
            CO_REQUEST,  
            CO_RESPONSE, 
            CO_REQUEST,  
            CO_RESPONSE, 
            CO_REQUEST,  
            CO_REQUEST,  
            CO_REQUEST,  
            CO_RESPONSE, 
            CO_REQUEST,  
            CO_RESPONSE, 
            CO_REQUEST,  
            CO_RESPONSE };

static void cassandra_parser(dpi_packet_t *p)
{
    cassandra_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not cassandra: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        data->client.header_cnt = 0;
        data->server.header_cnt = 0;
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    cassandra_wing_t *w;
    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        uint32_t shift = u32_distance(dpi_pkt_seq(p), w->seq);
        ptr = dpi_pkt_ptr(p) + shift;
        len = dpi_pkt_len(p) - shift;
    } else {
        dpi_fire_parser(p);
        return;
    }
    if (is_cassandra_internode(ptr, len)) {
        p->ep->cassandra_svr = true;
        dpi_finalize_parser(p);
        DEBUG_LOG(DBG_PARSER, p, "cassandra inter-node\n");
        return;
    }
    //check cassandra client request
    bool direction = ptr[0] & 0x80;
    uint8_t version = ptr[0] & 0x7F;
    if (dpi_is_client_pkt(p)) {
        if (direction) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not cassandra: It is a response from a client\n");
            return;
        }
    } else {
        if (!direction) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not cassandra: It is a request from a server\n");
            return;
        }
    }
    uint32_t    packet_len;
    uint32_t    opcode;
    if (version < 3) {
        if (len < 8) {
            return;
        }
        opcode = ptr[3];
        packet_len = ntohl(*(uint32_t *)(ptr+4));
    } else if (version <= 4) {
        if (len < 9) {
            return;
        }
        opcode = ptr[4];
        packet_len = ntohl(*(uint32_t *)(ptr+5));
    } else {
        dpi_fire_parser(p);
        DEBUG_LOG(DBG_PARSER, p, "Not cassandra: version should be 0-4\n");
        return;
    } 
    if (opcode >= sizeof(ca_opcode)) {
        dpi_fire_parser(p);
        DEBUG_LOG(DBG_PARSER, p, "Invalid cassandra opcode\n");
        return;
    }
    if (ca_opcode[opcode] != direction) {
        dpi_fire_parser(p);
        DEBUG_LOG(DBG_PARSER, p, "Invalid cassandra opcode and direction\n");
        return;
    }
    if ((packet_len + 9) > MAX_FRAME_LENGTH) {
        dpi_fire_parser(p);
        DEBUG_LOG(DBG_PARSER, p, "Invalid cassandra opcode and direction\n");
        return;
    }
    if (w->header_cnt != 0xff) {
        w->header_cnt ++;
    }
    dpi_set_asm_seq(p, w->seq+len);
    w->seq = w->seq + len;
    if ((data->client.header_cnt && data->server.header_cnt)) {
        p->ep->cassandra_svr = true;
        dpi_finalize_parser(p);
        dpi_ignore_parser(p);
        DEBUG_LOG(DBG_PARSER, p, "cassandra client, port: %d\n",p->sport);
    }
}

static void cassandra_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void cassandra_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_cassandra = {
    .new_session = cassandra_new_session,
    .delete_data = cassandra_delete_data,
    .parser = cassandra_parser,
    .name = "cassandra",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_CASSANDRA,
};

dpi_parser_t *dpi_cassandra_parser(void)
{
    return &dpi_parser_cassandra;
}


