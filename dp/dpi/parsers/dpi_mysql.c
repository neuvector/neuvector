#include <string.h>

#include "dpi/dpi_module.h"

#define MYSQL_HDR_LEN 4

#define MYSQL_SERVER_GREET          0
#define MYSQL_CLIENT_LOGIN          1
#define MYSQL_LOGIN_RESPONSE        2
#define MYSQL_AUTH_SWITCH_REQUEST   3
#define MYSQL_AUTH_SWITCH_RESPONSE  4
#define MYSQL_REQUEST               5

#define MYSQL_CAP1_LONG_PASSWORD                  0x0001
#define MYSQL_CAP1_FOUND_ROWS                     0x0002
#define MYSQL_CAP1_LONG_FLAG                      0x0004
#define MYSQL_CAP1_CONNECT_WITH_DB                0x0008
#define MYSQL_CAP1_NO_SCHEMA                      0x0010
#define MYSQL_CAP1_COMPRESS                       0x0020
#define MYSQL_CAP1_ODBC                           0x0040
#define MYSQL_CAP1_LOCAL_FILES                    0x0080
#define MYSQL_CAP1_IGNORE_SPACE                   0x0100
#define MYSQL_CAP1_PROTOCOL_41                    0x0200
#define MYSQL_CAP1_INTERACTIVE                    0x0400
#define MYSQL_CAP1_SSL                            0x0800
#define MYSQL_CAP1_IGNORE_SIGPIPE                 0x1000
#define MYSQL_CAP1_TRANSACTIONS                   0x2000
#define MYSQL_CAP1_RESERVED                       0x4000
#define MYSQL_CAP1_SECURE_CONNECTION              0x8000

#define MYSQL_CAP2_MULTI_STATEMENTS               0x0001
#define MYSQL_CAP2_MULTI_RESULTS                  0x0002
#define MYSQL_CAP2_PS_MULTI_RESULTS               0x0004
#define MYSQL_CAP2_PLUGIN_AUTH                    0x0008
#define MYSQL_CAP2_CONNECT_ATTRS                  0x0010
#define MYSQL_CAP2_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x0020
#define MYSQL_CAP2_CAN_HANDLE_EXPIRED_PASSWORDS   0x0040
#define MYSQL_CAP2_SESSION_TRACK                  0x0080
#define MYSQL_CAP2_DEPRECATE_EOF                  0x0100

/* MySQL command codes */
#define MYSQL_SLEEP               0  /* not from client */
#define MYSQL_QUIT                1
#define MYSQL_INIT_DB             2
#define MYSQL_QUERY               3
#define MYSQL_FIELD_LIST          4
#define MYSQL_CREATE_DB           5
#define MYSQL_DROP_DB             6
#define MYSQL_REFRESH             7
#define MYSQL_SHUTDOWN            8
#define MYSQL_STATISTICS          9
#define MYSQL_PROCESS_INFO        10
#define MYSQL_CONNECT             11 /* not from client */
#define MYSQL_PROCESS_KILL        12
#define MYSQL_DEBUG               13
#define MYSQL_PING                14
#define MYSQL_TIME                15 /* not from client */
#define MYSQL_DELAY_INSERT        16 /* not from client */
#define MYSQL_CHANGE_USER         17
#define MYSQL_BINLOG_DUMP         18 /* replication */
#define MYSQL_TABLE_DUMP          19 /* replication */
#define MYSQL_CONNECT_OUT         20 /* replication */
#define MYSQL_REGISTER_SLAVE      21 /* replication */
#define MYSQL_STMT_PREPARE        22
#define MYSQL_STMT_EXECUTE        23
#define MYSQL_STMT_SEND_LONG_DATA 24
#define MYSQL_STMT_CLOSE          25
#define MYSQL_STMT_RESET          26
#define MYSQL_SET_OPTION          27
#define MYSQL_STMT_FETCH          28

#define EOF_PACKET                                0xfe
#define ERR_PACKET                                0xff

#define ER_DBACCESS_DENIED_ERROR                  1044 
#define ER_ACCESS_DENIED_ERROR                    1045 

#define MYSQL_MAX_USERNAME_LENGTH    32

typedef struct ssl_wing_ {
    u_int32_t seq;
} ssl_wing_t;

typedef struct ssl_data_ {
    ssl_wing_t client, server;
    uint8_t state;
    uint16_t client_cap;
    uint16_t client_cap_ext;
    char user_name[MYSQL_MAX_USERNAME_LENGTH];
} ssl_data_t;

extern void check_sql_query(dpi_packet_t *p, uint8_t *query, int len, int app);

static int server_greet(dpi_packet_t *p, uint8_t *ptr, int pkt_len)
{
    int len = pkt_len;
    uint8_t *end = ptr + len;
    uint8_t ver = *ptr;
    ptr ++; len --;

    if (ver == 10) {
        uint8_t *eos = consume_string(ptr, len);
        if (eos == NULL) return -1;

        char *sver = (char *)ptr;
        uint8_t sver_len = eos - ptr;

        ptr = eos + 1; len = end - ptr;

        // connection_id (4) + salt (8 + eos) + cap1 (2) = 15
        if (len < 15) return -1;
        ptr += 15; len -= 15;
        uint16_t cap1 = GET_LITTLE_INT16(ptr - 2);

        if (len == 0) {
            DEBUG_LOG(DBG_PARSER, p, "MySQL: short greeting\n");
            dpi_ep_set_server_ver(p, sver, sver_len);
            return pkt_len;
        }

        // char set (1) + status (2) + cap2 (2) + auth len (1) + unused (10) = 16
        if (len < 16) return -1;

        uint16_t cap2 = GET_LITTLE_INT16(ptr + 3);

        uint8_t auth_len = 0;
        if (cap2 & MYSQL_CAP2_PLUGIN_AUTH) {
            auth_len = ptr[5];
        } else {
            if (ptr[5] != 0) return -1;
        }

        // 10 unused bytes must be all 0
        //NVSHAS-5876, some server greet unused byte
        //contains non-zero
        //int i;
        ptr += 6; len -= 6;
        /*for (i = 0; i < 10; i ++) {
            if (ptr[i] != 0) return -1;
        }*/
        ptr += 10; len -= 10;

        if (cap1 & MYSQL_CAP1_SECURE_CONNECTION) {
            // max. 13 including eos
            eos = consume_string(ptr, len);
            if (eos == NULL || eos - ptr > 12) return -1;
            ptr = eos + 1; len = end - ptr;
        }

        if (cap2 & MYSQL_CAP2_PLUGIN_AUTH) {
            eos = consume_string(ptr, len);
            if (eos == NULL || eos - ptr != auth_len) return -1;
            ptr = eos + 1;
        }

        // end is reached
        if (ptr != end) return -1;

        dpi_ep_set_server_ver(p, sver, sver_len);
        return pkt_len;
    } else if (ver == 9) {
        uint8_t *eos = consume_string(ptr, len);
        if (eos == NULL) return -1;

        char *sver = (char *)ptr;
        uint8_t sver_len = eos - ptr;

        ptr = eos + 1; len = end - ptr;

        // connection_id (4) + salt (eos string)
        if (len < 4) return -1;
        ptr += 4; len -= 4;

        eos = consume_string(ptr, len);
        if (eos == NULL) return -1;

        // end is reached
        if (ptr != end) return -1;

        dpi_ep_set_server_ver(p, sver, sver_len);
        return pkt_len;
    }

    return -1;
}

void get_user_name(uint8_t *ptr, int len, uint16_t cap, char * user_name)
{
    char *resp_ptr = (char *)ptr;
    int  left = len;

    if (cap & MYSQL_CAP1_PROTOCOL_41) {
        resp_ptr += 28;
        left     -= 28;
    } else {
        resp_ptr += 3;
        left     -= 3;
    }
    if (left < 1) {
        return;
    }
    // Username is zero-terminated.
    strlcpy(user_name, resp_ptr, MYSQL_MAX_USERNAME_LENGTH);
}

static void mysql_parser(dpi_packet_t *p)
{
    ssl_data_t *data;
    ssl_wing_t *w;
    uint8_t *ptr;
    uint32_t len, expect;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        // First packet must be from server
        if (dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not MySQL: First packet from client\n");
            dpi_fire_parser(p);
            return;
        }
        // Quick check of packet sequence and version
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
        if (len < 5 || ptr[3] != 0 || (ptr[4] != 10 && ptr[4] != 9)) {
            DEBUG_LOG(DBG_PARSER, p, "Not MySQL: Wrong number or version\n");
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
        data->state = MYSQL_SERVER_GREET;

        dpi_put_parser_data(p, data);
    }

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

    while (len >= MYSQL_HDR_LEN) {
        expect = GET_LITTLE_INT24(ptr);

        switch (data->state) {
        case MYSQL_SERVER_GREET:
            if (dpi_is_client_pkt(p)) {
                DEBUG_LOG(DBG_PARSER, p, "Not MySQL: First packet from client\n");
                dpi_fire_parser(p);
                return;
            }
#define MYSQL_MAX_SERVER_GREETING_LEN 128
            if (expect > MYSQL_MAX_SERVER_GREETING_LEN) {
                DEBUG_LOG(DBG_PARSER, p, "Not MySQL: Server greeting too long\n");
                dpi_fire_parser(p);
                return;
            }

            if (len < expect + MYSQL_HDR_LEN) {
                // Wait for full packet
                return;
            }

            ptr += MYSQL_HDR_LEN;
            len -= MYSQL_HDR_LEN;

            if (server_greet(p, ptr, expect) == -1) {
                DEBUG_LOG(DBG_PARSER, p, "Not MySQL: Wrong format\n");
                dpi_fire_parser(p);
                return;
            }
            data->state = MYSQL_CLIENT_LOGIN;
            dpi_finalize_parser(p);
            //dpi_ignore_parser(p);

            ptr += expect;
            len -= expect;

            break;
        case MYSQL_CLIENT_LOGIN:
            if (!dpi_is_client_pkt(p)) {
                DEBUG_LOG(DBG_PARSER, p, "login packet from server\n");
                dpi_ignore_parser(p);
                return;
            }
            //wait more data, but skip the data already parsed
            if (len < (MYSQL_HDR_LEN+expect)) {
                w->seq = dpi_ptr_2_seq(p, ptr);
                dpi_set_asm_seq(p, w->seq);
                return;
            }
            ptr += MYSQL_HDR_LEN; len -= MYSQL_HDR_LEN;

            data->client_cap = GET_LITTLE_INT16(ptr);
            data->client_cap_ext = GET_LITTLE_INT16(ptr+2);
            if (data->client_cap & MYSQL_CAP1_SSL) {
                DEBUG_LOG(DBG_PARSER, p, "SSL request\n");
                dpi_ignore_parser(p);
            }

            get_user_name(ptr + 4, len - 4, data->client_cap, data->user_name);
            data->state = MYSQL_LOGIN_RESPONSE;
            ptr += expect; len -= expect;
            break;
        case MYSQL_LOGIN_RESPONSE:
            if (dpi_is_client_pkt(p)) {
                DEBUG_LOG(DBG_PARSER, p, "Response packet from client\n");
                //dpi_ignore_parser(p);
                return;
            }
            //wait more data, but skip the data already parsed
            if (len < (MYSQL_HDR_LEN+expect)) {
                w->seq = dpi_ptr_2_seq(p, ptr);
                dpi_set_asm_seq(p, w->seq);
                return;
            }
            ptr += MYSQL_HDR_LEN; len -= MYSQL_HDR_LEN;
            uint8_t header = ptr[0];
            if (header == ERR_PACKET) {
                uint16_t error_code = GET_LITTLE_INT16((ptr+1));
                if (error_code == ER_ACCESS_DENIED_ERROR || error_code == ER_DBACCESS_DENIED_ERROR) {
                    DEBUG_LOG(DBG_PARSER, p, "Login Denied, user=%s\n", data->user_name);
                    dpi_threat_trigger_flip(DPI_THRT_MYSQL_ACCESS_DENY, p, "user=%s", data->user_name);
                }
            }
            if (data->client_cap_ext & MYSQL_CAP2_PLUGIN_AUTH) {
                data->state = MYSQL_AUTH_SWITCH_REQUEST;
            } else {
                data->state = MYSQL_REQUEST;
            }
            ptr += expect; len -= expect;
            break;
        case MYSQL_AUTH_SWITCH_REQUEST:
            ptr += MYSQL_HDR_LEN; len -= MYSQL_HDR_LEN;
            uint8_t status_tag = ptr[0];
            if (status_tag == EOF_PACKET) {
                data->state = MYSQL_AUTH_SWITCH_RESPONSE;
                ptr += expect; len -= expect;
            } else {
                data->state = MYSQL_REQUEST;
                ptr -= MYSQL_HDR_LEN; len += MYSQL_HDR_LEN;
            }
            break;
        case MYSQL_AUTH_SWITCH_RESPONSE:
            ptr += MYSQL_HDR_LEN; len -= MYSQL_HDR_LEN;
            /*if (!dpi_is_client_pkt(p)) {
                DEBUG_LOG(DBG_PARSER, p, "Auth response from server\n");
                dpi_ignore_parser(p);
                return;
            }*/
            data->state = MYSQL_REQUEST;
            ptr += expect; len -= expect;
            break;
        case MYSQL_REQUEST:
#define MYSQL_MAX_QUERY_LEN 4000
            if (expect > MYSQL_MAX_QUERY_LEN || expect == 0) {
                DEBUG_LOG(DBG_PARSER, p, "Invalid MySQL query length: %d\n", expect);
                dpi_fire_parser(p);
                return;
            }
            //wait more data, but skip the data already parsed
            if (len < (MYSQL_HDR_LEN+expect)) {
                w->seq = dpi_ptr_2_seq(p, ptr);
                dpi_set_asm_seq(p, w->seq);
                return;
            }
            ptr += MYSQL_HDR_LEN; len -= MYSQL_HDR_LEN;
            if (dpi_is_client_pkt(p)) {
                uint8_t opcode = ptr[0];
                if (opcode == MYSQL_QUERY && expect > 1) {
                    //embedded sql injection threat detection
                    check_sql_query(p, ptr+1, expect-1, DPI_APP_MYSQL);
                } else if (opcode == MYSQL_QUIT) {
                    dpi_ignore_parser(p);
                }
            }
            ptr += expect; len -= expect;
            break;
        default:
            DEBUG_LOG(DBG_PARSER, p, "Not MySQL: Wrong state\n");
            dpi_fire_parser(p);
            return;
        }
    }
    w->seq = dpi_ptr_2_seq(p, ptr);
    dpi_set_asm_seq(p, w->seq);
}

static void mysql_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void mysql_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_mysql = {
    .new_session = mysql_new_session,
    .delete_data = mysql_delete_data,
    .parser = mysql_parser,
    .name = "mysql",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_MYSQL,
};

dpi_parser_t *dpi_mysql_parser(void)
{
    return &dpi_parser_mysql;
}
