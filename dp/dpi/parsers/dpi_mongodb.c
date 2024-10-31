#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

typedef struct mongodb_wing_ {
    uint32_t seq;
    uint32_t req_id;
} mongodb_wing_t;

typedef struct mongodb_data_ {
    mongodb_wing_t client, server;
    uint32_t client_pkt_size;
    uint32_t client_pkt_parsed;
    bool     client_req;
} mongodb_data_t;

//refer to util/net/message.h in mongodb src, enum NetworkOp
static bool mongodb_check_opcode(uint32_t op_code, bool client)
{
    switch (op_code) {
    case 0://Invalid
        return false;
    case 1://database Reply
        return !client;
    case 1000://Message 
        return true;
    case 2001: //Update
    case 2002: //Insert
    case 2003: //reservered , GetByOID formerly
    case 2004: //Query
    case 2005: //GetMore
    case 2006: //Delete
    case 2007: //KillCursors
        return client;
    case 2008:
    case 2009:
        return false;
    case 2010:
        return client;
    case 2011:
        return !client;
    default:
        return false;
    }

} 
static void mongodb_parser(dpi_packet_t *p)
{
    mongodb_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not mongodb: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    mongodb_wing_t *w;
    bool client = dpi_is_client_pkt(p);
    w = client ? &data->client : &data->server;
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
    if (client && data->client_req) {
        data->client_pkt_parsed += len;
        if (data->client_pkt_parsed > (data->client_pkt_size+16)) {
            DEBUG_LOG(DBG_PARSER, p, "Not client request packet too much=%d, size\n", data->client_pkt_parsed, data->client_pkt_size);
            dpi_fire_parser(p);
        }
        DEBUG_LOG(DBG_PARSER, p, "Pass client packet len=%d, size\n", data->client_pkt_parsed, data->client_pkt_size);
        dpi_set_asm_seq(p, w->seq+len);
        w->seq = w->seq + len;
        return;
    }
    if (len < 16) {
        return;
    }
    uint32_t size        = htole32(*(uint32_t *)(ptr));
    uint32_t request_id  = htole32(*(uint32_t *)(ptr+4));
    uint32_t response_to  = htole32(*(uint32_t *)(ptr+8));
    uint32_t op_code     = htole32(*(uint32_t *)(ptr+12));
    if (!mongodb_check_opcode(op_code,client)) {
        DEBUG_LOG(DBG_PARSER, p, "Not mongodb: invalid opcode=%d\n", op_code);
        dpi_fire_parser(p);
        return;
    }
    if (client) {
        if (response_to != 0) {
            DEBUG_LOG(DBG_PARSER, p, "Client response_to not zero=%d\n", response_to);
            dpi_fire_parser(p);
            return;
        }
        data->client.req_id     = request_id;
        data->client_pkt_size   = size;
        data->client_pkt_parsed = len;
        data->client_req        = true;
        DEBUG_LOG(DBG_PARSER, p, "Valid client request size=%d request_id=%d response_to=%d op_code=%d\n", size, request_id, response_to, op_code);
    } else {
        if (data->client_req && data->client.req_id == response_to) {
            DEBUG_LOG(DBG_PARSER, p, "Valid server response request_id=%d response_to=%d op_code=%d\n", request_id, response_to, op_code);
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        } else {
            DEBUG_LOG(DBG_PARSER, p, "Not mongodb server response\n");
            dpi_fire_parser(p);
            return;
        }
    }

    dpi_set_asm_seq(p, w->seq+len);
    w->seq = w->seq + len;
}

static void mongodb_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void mongodb_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_mongodb = {
    .new_session = mongodb_new_session,
    .delete_data = mongodb_delete_data,
    .parser = mongodb_parser,
    .name = "mongodb",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_MONGODB,
};

dpi_parser_t *dpi_mongodb_parser(void)
{
    return &dpi_parser_mongodb;
}


