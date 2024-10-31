#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define MAGIC_REQUEST         0x80
#define MAGIC_RESPONSE        0x81
#define SASL_LIST_MECHS       0x20
#define SASL_AUTH             0x21
#define SASL_STEP             0x22

typedef struct sasl_code_ {
    char *name;
    uint8_t len;
} sasl_code_t;

const static sasl_code_t sasl_code[] = {
    {"PLAIN",           sizeof("PLAIN")},
    {"CRAM-MD5",        sizeof("CRAM-MD5")},
    {"SCRAM-SHA1",      sizeof("SCRAM-SHA1")},
    {"SCRAM-SHA256",    sizeof("SCRAM-SHA256")},
    {"SCRAM-SHA512",    sizeof("SCRAM-SHA512")}
};

typedef enum {
    RAW_BYTES = 0x00,
    DATATYPE_JSON = 0x01,
    /* Compressed == snappy compression */
    DATATYPE_COMPRESSED = 0x02,
    /* Compressed == snappy compression */
    DATATYPE_COMPRESSED_JSON = 0x03
} protocol_binary_datatypes;

typedef struct couchbase_wing_ {
    uint32_t seq;
    uint32_t op_code;
    uint32_t req_id;
} couchbase_wing_t;

typedef struct couchbase_data_ {
    couchbase_wing_t client, server;
    uint8_t client_request:1,
            port_map_req  :1,
            erldp_req  :1,
            erldp_resp  :1;
    uint8_t port_map_req_code;
} couchbase_data_t;

#define EPMD_NAME_REQ      'n' /* 0x6e */
#define EPMD_ALIVE2_REQ    'x' /* 0x78 */
#define EPMD_PORT2_REQ     'z' /* 0x7a */
#define EPMD_ALIVE2_RESP   'y' /* 0x79 */
#define EPMD_PORT2_RESP    'w' /* 0x77 */


#define R3_hidden_node  72
#define R3_erlang_node  77
#define R4_hidden_node 104
#define R4_erlang_node 109
#define R6_nodes       110

static bool erlang_port_map_req(uint8_t * ptr, uint32_t len, couchbase_data_t *data)
{
    ptr += 2;
    if (ptr[0] == EPMD_PORT2_REQ) {
        data->port_map_req_code = EPMD_PORT2_REQ;
        return true;
    } else if (ptr[0] == EPMD_ALIVE2_REQ) {
        if (len < 12) return false;

        ptr ++;
        ptr += 2;
        uint8_t node_type = ptr[0];
        ptr ++;
        uint8_t protocol = ptr[0];

        if (node_type != R3_hidden_node &&
            node_type != R3_erlang_node &&
            node_type != R4_hidden_node &&
            node_type != R4_erlang_node &&
            node_type != R6_nodes ) {
            return false;
        }

        if (protocol != 0) return false;

        data->port_map_req_code = EPMD_ALIVE2_REQ;
        return true;
    } else {
        return false;
    }
}

//0  , not erldp response
//1  , erldp response
//2  , finalize 
static int erlang_dp_req(uint8_t * ptr, uint32_t len, couchbase_data_t *data)
{
    if (len < 5) return 0;

    uint16_t pkg_len    = GET_BIG_INT16(ptr);
    uint8_t  tag = ptr[2];
    int left = len;
    ptr += 3; left -= 3;
    if (pkg_len > 256 || (tag != 'n' && tag != 'r' && tag != 'a' && tag != 's')) {
        return 0;
    }
    if (tag == 'n') {
        uint16_t ver    = GET_BIG_INT16(ptr);
        if (ver > 0x10) {
            return 0;
        }
        return 1;
    } else {
        if (tag  == 's') {
            if ( ((left >= 2 ) && (memcmp(ptr, "ok", 2) == 0)) ||
                 ((left >= 15) && (memcmp(ptr, "ok_simultaneous", 15) == 0)) ||
                 ((left >= 3 ) && (memcmp(ptr, "nok", 3) == 0)) ||
                 ((left >= 11) && (memcmp(ptr, "not_allowed", 11) == 0)) ||
                 ((left >= 5 ) && (memcmp(ptr, "alive", 5) == 0))) {
                return 2;
            }
        }
        return 1;
    }
}

static bool erlang_port_map_resp(uint8_t *ptr, uint32_t len, couchbase_data_t *data)
{
    if (ptr[0] == EPMD_PORT2_RESP) {
        if (data->port_map_req_code != EPMD_PORT2_REQ) return false;
        if (len < 12) return false;

        /*
        if (ptr[1] == 0) { // result
            uint16_t port = GET_BIG_INT16(ptr + 2);
        }
        */

        ptr += 2;
        ptr += 2;
        uint8_t node_type = ptr[0];
        ptr ++;
        uint8_t protocol = ptr[0];

        if (node_type != R3_hidden_node &&
            node_type != R3_erlang_node &&
            node_type != R4_hidden_node &&
            node_type != R4_erlang_node &&
            node_type != R6_nodes ) {
            return false;
        }

        if (protocol != 0) return false;

        return true;
    } else if (ptr[0] == EPMD_ALIVE2_RESP) {

        if (data->port_map_req_code != EPMD_ALIVE2_REQ) return false;
        return true;
    } else {
        return false;
    }
}

static bool find_sasl_mechinsm(uint8_t * ptr, uint32_t len)
{
    uint32_t left = len;
    int i;
    while (left >= (sasl_code[0].len-1)) {
        for (i=0; i< sizeof(sasl_code)/sizeof(sasl_code[0]); i++) {
            if (left >= (sasl_code[i].len-1)) {
                if (memcmp(ptr, sasl_code[i].name, sasl_code[i].len-1) == 0) {
                    return true;
                }
            } 
        } 
        ptr++; left--;
    }
    return false;
}

static void couchbase_parser(dpi_packet_t *p)
{
    couchbase_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not couchbase: First packet from server\n");
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

    couchbase_wing_t *w;
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
    bool client = dpi_is_client_pkt(p);
    if (len < 4) {
        return;
    }
    uint32_t magic      = ptr[0];
    uint32_t opcode     = ptr[1];
    uint32_t key_len    = GET_BIG_INT16(ptr+2);
    uint32_t data_type;
    int      i;

    if (client) {
        //check erlang port mapper daemon
        if (erlang_port_map_req(ptr, len, data)) {
            data->port_map_req = true;
            DEBUG_LOG(DBG_PARSER, p, "couchbase port mapper request\n");
            w->seq += len;
            dpi_set_asm_seq(p, w->seq);
            return;
        } else if (erlang_dp_req(ptr, len, data)) {
            if (data->erldp_req && data->erldp_resp) {
                dpi_finalize_parser(p);
                dpi_ignore_parser(p);
            }
            data->erldp_req = true;
            w->seq += len;
            dpi_set_asm_seq(p, w->seq);
            DEBUG_LOG(DBG_PARSER, p, "erlang dp request\n");
            return;
        } else if (magic != MAGIC_REQUEST) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not couchbase client request\n");
            return;
        }
        data_type  = ptr[5];
        if (data_type > DATATYPE_COMPRESSED_JSON) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not couchbase client request,error data_type: %d\n",data_type);
            return;
        }
        if (opcode == SASL_LIST_MECHS) {
            if (len < 24) return;
            //this client list mechnism packet should be all 0 in the left
            for (i=2; i<24; i++) {
                //except opaque
                if ((i <12 || i > 15) && ptr[i]) {
                    DEBUG_LOG(DBG_PARSER, p, "Not couchbase client SASL_LIST_MECHS request\n");
                    dpi_fire_parser(p);
                    return;
                }
            }
            DEBUG_LOG(DBG_PARSER, p, "Couchbase client SASL_LIST_MECHS request\n");
        } else if ( opcode == SASL_AUTH) {
            //small than the less sasl code length
            if (len < (24+(sasl_code[0].len-1))) {
                return;
            }
            //check whether there is one sasl code
            key_len = key_len > (len-24) ? (len-24): key_len;
            if (!find_sasl_mechinsm(ptr+24, key_len)) {
                DEBUG_LOG(DBG_PARSER, p, "Not couchbase client sasl request\n");
                dpi_fire_parser(p);
                return;
            }
            DEBUG_LOG(DBG_PARSER, p, "Couchbase client SASL_AUTH request\n");
        } else {
            DEBUG_LOG(DBG_PARSER, p, "Not couchbase client sasl request\n");
            dpi_fire_parser(p);
            return;
        }
        w->op_code = opcode;
        data->client_request = true;
        w->seq += len;
        dpi_set_asm_seq(p, w->seq);

    } else { 
        //server response
        if (data->port_map_req) {
            if (erlang_port_map_resp(ptr, len, data)) {
                dpi_finalize_parser(p);
                dpi_ignore_parser(p);
                if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
                    p->ep->couchbase_svr = true;
                } else {
                    p->ep->couchbase_clt = true;
                }
                return;
            } else {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Not couchbase port map response\n");
                return;
            }
        }else if (data->erldp_req) {
            int ret = erlang_dp_req(ptr, len, data);
            if (ret == 0) {
                //consider it as full packet 
                DEBUG_LOG(DBG_PARSER, p, "Not erldp response\n");
                dpi_fire_parser(p);
                return;
            } else {
                DEBUG_LOG(DBG_PARSER, p, "erldp response\n");
                if (ret == 2 || (data->erldp_req && data->erldp_resp)) {
                    dpi_finalize_parser(p);
                    dpi_ignore_parser(p);
                }
                data->erldp_resp = true;
                w->seq += len;
                dpi_set_asm_seq(p, w->seq);
                return;
            }
        } else if (magic != MAGIC_RESPONSE) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not couchbase server response: %x\n",magic);
            return;
        }
        if (opcode == SASL_LIST_MECHS) {
            //match with client sasl list request
            if (!data->client_request || (data->client.op_code != SASL_LIST_MECHS)) {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Not couchbase server SASL_LIST_MECHS\n");
                return;
            }

            if (len < (24+(sasl_code[0].len-1))) {
                return;
            }
            uint32_t total_body    = GET_BIG_INT32(ptr+8);
            if ((total_body < (sasl_code[0].len-1)) || (total_body > 256)) {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Not couchbase server SASL_LIST_MECHS response,total_body: %d\n", total_body);
                return;
            }

            if (!find_sasl_mechinsm(ptr+24, (len-24))) {
                DEBUG_LOG(DBG_PARSER, p, "Not Couchbase server SASL_LIST_MECHS response\n");
                dpi_fire_parser(p);
                return;
            }
            DEBUG_LOG(DBG_PARSER, p, "Couchbase server SASL_LIST_MECHS response\n");

        } else if ( opcode == SASL_AUTH) {
            //match with client sasl list request
            if (!data->client_request || (data->client.op_code != SASL_AUTH)) {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Not couchbase server SASL_AUTH\n");
                return;
            }
            if (len < 24) return;

            //the server sasl auth packet should be all 0 in the left
            for (i=2; i<24; i++) {
                if (ptr[i]) {
                    DEBUG_LOG(DBG_PARSER, p, "Not couchbase client SASL_LIST_MECHS request\n");
                    dpi_fire_parser(p);
                    return;
                }
            }
            DEBUG_LOG(DBG_PARSER, p, "Couchbase server SASL_AUTH response\n");
        } else {
            DEBUG_LOG(DBG_PARSER, p, "Not couchbase server SASL response\n");
            dpi_fire_parser(p);
            return;
        }

        dpi_finalize_parser(p);
        dpi_ignore_parser(p);
        if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
            p->ep->couchbase_svr = true;
        } else {
            p->ep->couchbase_clt = true;
        }
    }
}

static void couchbase_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void couchbase_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_couchbase = {
    .new_session = couchbase_new_session,
    .delete_data = couchbase_delete_data,
    .parser = couchbase_parser,
    .name = "couchbase",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_COUCHBASE,
};

dpi_parser_t *dpi_couchbase_parser(void)
{
    return &dpi_parser_couchbase;
}


