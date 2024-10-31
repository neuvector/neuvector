#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define VALID_LONG_MESSAGE_TYPE(id) \
	((id) == 'T' || (id) == 'D' || (id) == 'd' || (id) == 'V' || \
	 (id) == 'E' || (id) == 'N' || (id) == 'A')
#define MAX_STARTUP_PACKET_LENGTH 10000

#define POSTGRESQL_HEADER_LEN 5
#define POSTGRESQL_LENGTH_LEN 4
#define POSTGRESQL_CANCEL_REQUEST   0x04d2162e
#define POSTGRESQL_SSL_REQUEST      0x04d2162f
#define POSTGRESQL_STARTUP_MESSAGE  0x30000

#define PGSQL_CMD_PASSWORD_MESSAGE  'p'
#define PGSQL_CMD_SIMPLE_QUERY      'Q'
#define PGSQL_CMD_PARSE             'P'
#define PGSQL_CMD_BIND              'B'
#define PGSQL_CMD_EXECUTE           'E'
#define PGSQL_CMD_DESCRIBE          'D'
#define PGSQL_CMD_CLOSE             'C'
#define PGSQL_CMD_FLUSH             'H'
#define PGSQL_CMD_SYNC              'S'
#define PGSQL_CMD_FUNCTION_CALL     'F'
#define PGSQL_CMD_COPY_DATA         'd'
#define PGSQL_CMD_COPY_COMPLETION   'c'
#define PGSQL_CMD_COPY_FAILURE      'f'
#define PGSQL_CMD_TERMINATION       'X'
#define PGSQL_CMD_AUTH_REQUEST      'R'

#define PGSQL_MSG_NOTICE            'N'
#define PGSQL_MSG_ERROR             'E'


typedef struct postgresql_wing_ {
    uint32_t seq;
} postgresql_wing_t;

typedef struct postgresql_data_ {
    postgresql_wing_t client, server;
    uint8_t  cancel_request;
    uint8_t  ssl_request;
    uint8_t  startup_message;
} postgresql_data_t;

extern void check_sql_query(dpi_packet_t *p, uint8_t *query, int len, int app);

static void postgresql_parser(dpi_packet_t *p)
{
    postgresql_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not postgresql: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        data->cancel_request  = 0;
        data->ssl_request     = 0;
        data->startup_message = 0;
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    postgresql_wing_t *w;
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
    //reference to interfaces/libpq/fe-connect.c and fe-protocol3.c in postgre src
    //check server respone, S for support ssl, N for not
    uint8_t type = ptr[0]; 
    uint32_t length;
    if (dpi_is_parser_final(p)) {
        while (len > POSTGRESQL_HEADER_LEN) {
            type = ptr[0];
            ptr ++; len --;
            length = ntohl(*(uint32_t *)ptr);
#define PGSQL_MAX_PACKET_SIZE 30000
            if (length > PGSQL_MAX_PACKET_SIZE || length < 4) {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Invalid Postgre Sql query length: %d\n", length);
                return;
            } else if (length > len) {
                //wait for more data
                ptr --;
                break;
            }
            if (type == PGSQL_CMD_SIMPLE_QUERY) {
               if (!dpi_is_client_pkt(p)) {
                   dpi_fire_parser(p);
                   DEBUG_LOG(DBG_PARSER, p, "Postgresql query should not from server\n");
                   return;
               }
               //embedded sql injection threat detection
               check_sql_query(p, ptr+4, length-4, DPI_APP_POSTGRESQL);
            }
            ptr += length; len -= length;
        }
    }else if (!dpi_is_client_pkt(p)) {
        ptr ++;
        if (len == 1 &&
            (type == PGSQL_CMD_SYNC || type == PGSQL_MSG_NOTICE || type == PGSQL_CMD_EXECUTE) &&
            data->ssl_request) {
            DEBUG_LOG(DBG_PARSER, p, "Postgre Sql server response to ssl\n");
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        } else if (len < POSTGRESQL_HEADER_LEN) {
            DEBUG_LOG(DBG_PARSER, p, "Not enough Postgre Sql server data\n");
            return;
        } else { 
            len --;
            length = ntohl(*(uint32_t *)ptr);
            if (length < POSTGRESQL_LENGTH_LEN) {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Invalid Postgre Sql message length\n");
                return;
            } else if (length > PGSQL_MAX_PACKET_SIZE && !VALID_LONG_MESSAGE_TYPE(type)) {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Invalid Postgre Sql long message: %d, %c\n",length, type);
                return;
            }
            if ((type == PGSQL_CMD_AUTH_REQUEST || type == PGSQL_MSG_ERROR) &&
                (data->startup_message || data->cancel_request)) {
                dpi_finalize_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Postgre Sql server response to start up message\n");
                // if not checking sql injection, ignore it
                //if (data->ssl_request) {
                dpi_ignore_parser(p);
                //}
            } else {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Postgre Sql server should respond to start up message first\n");
            } 
            if (length > len) {
                ptr += len;
            } else {
                ptr += length;
            }
        }
    } else {
        //check postgresql client request
        if (len < POSTGRESQL_LENGTH_LEN) {
            return ;
        }
        if (type != '\0') {
            ptr ++;
            len --;
        }
        length = ntohl(*(uint32_t *)ptr);
        if (length < 8 || length > MAX_STARTUP_PACKET_LENGTH) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Invalid Postgre Sql Startup message\n");
            return;
        }
        ptr += POSTGRESQL_LENGTH_LEN;
        len -= POSTGRESQL_LENGTH_LEN;
        if (type == '\0') {
            if (len < POSTGRESQL_LENGTH_LEN) {
                return ;
            }
            uint32_t tag = ntohl(*(uint32_t *)ptr);
            if (length == 16 && tag == POSTGRESQL_CANCEL_REQUEST) {
                data->cancel_request  = 1;
            } else if (length == 8 && tag == POSTGRESQL_SSL_REQUEST) {
                data->ssl_request     = 1;
            } else if (tag == POSTGRESQL_STARTUP_MESSAGE) {
                //only support protocal 3.0
                data->startup_message = 1;
            } else {
                dpi_fire_parser(p);
                DEBUG_LOG(DBG_PARSER, p, "Should be Postgre Sql Startup message first\n");
            }
        } else {
            //client should send the start message first
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not Postgre Sql Startup message\n");
        }
        // not the whole packet, should parse again.
        if ((length - POSTGRESQL_LENGTH_LEN) > len) {
            return;
        }
        ptr += length - POSTGRESQL_LENGTH_LEN;
    }
    w->seq = dpi_ptr_2_seq(p, ptr);
    dpi_set_asm_seq(p, w->seq);
}
static void postgresql_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void postgresql_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_postgresql = {
    .new_session = postgresql_new_session,
    .delete_data = postgresql_delete_data,
    .parser = postgresql_parser,
    .name = "postgresql",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_POSTGRESQL,
};

dpi_parser_t *dpi_postgresql_parser(void)
{
    return &dpi_parser_postgresql;
}


