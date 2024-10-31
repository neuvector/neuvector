#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define     NIO_BUFFER_LIMIT    (256 * 1024)
#define     MESSAGE_HEADER_LEN  (8+1+8+4)
#define     MESSAGE_ONEWAY_HEADER_LEN  (8+1+4)

typedef struct spark_wing_ {
    uint32_t seq;
    uint64_t request_id; 
} spark_wing_t;

typedef struct spark_data_ {
    spark_wing_t client, server;
    bool    client_request;
} spark_data_t;

static void spark_parser(dpi_packet_t *p)
{
    spark_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    spark_wing_t *w;
    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        uint32_t shift = u32_distance(dpi_pkt_seq(p), w->seq);
        ptr = dpi_pkt_ptr(p) + shift;
        len = dpi_pkt_len(p) - shift;
    } else {
        DEBUG_LOG(DBG_PARSER, p, "packet error\n");
        dpi_fire_parser(p);
        return;
    }

    if (dpi_is_client_pkt(p) && data->client_request) {
        dpi_set_asm_seq(p, w->seq+len);
        w->seq = w->seq + len;
        DEBUG_LOG(DBG_PARSER, p, "Skip spark request packet=%d\n", len);
        return;
    }
    if (len < 9) return;
    uint64_t size = be64toh(*(uint64_t *)(ptr));
    if (size > NIO_BUFFER_LIMIT) {
            DEBUG_LOG(DBG_PARSER, p, "spark request size too large=%d\n", size);
            dpi_fire_parser(p);
            return;
    }
    int8_t  msg_type = ptr[8];
    uint32_t msg_len,str_len;
    uint64_t request_id;
    ptr += 9;
    len -= 9;
    //refer to source code in spark/network/protocol/
    switch (msg_type) {
        case 0: // ChunkFetchRequest;
        case 1: // ChunkFetchSuccess;
        case 2: // ChunkFetchFailure;
            //chunk mode is unsupported in the current source of spark netty. 
            DEBUG_LOG(DBG_PARSER, p, "chunk mode is unsupported currently\n");
            dpi_fire_parser(p);
            return;
        case 3: // RpcRequest;
            if (len < (8+4)) return;
            request_id = be64toh(*(uint64_t *)(ptr));
            msg_len = ntohl(*(uint32_t *)(ptr+8));
            if (msg_len > NIO_BUFFER_LIMIT || (msg_len+MESSAGE_HEADER_LEN) != size) {
                DEBUG_LOG(DBG_PARSER, p, "Spark size mismatch,size=%d msg_len=%d\n", size, msg_len);
                dpi_fire_parser(p);
                return;
            }
            data->client.request_id = request_id;
            data->client_request = true;
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Valid spark request=%d\n", msg_type);
            break;
        case 4: // RpcResponse;
            if (len < (8+4)) return;
            request_id = be64toh(*(uint64_t *)(ptr));
            msg_len = ntohl(*(uint32_t *)(ptr+8));
            if (msg_len > NIO_BUFFER_LIMIT || (msg_len+MESSAGE_HEADER_LEN) != size) {
                DEBUG_LOG(DBG_PARSER, p, "Spark size mismatch,size=%d msg_len=%d\n", size, msg_len);
                dpi_fire_parser(p);
                return;
            }
            if (data->client_request){
                if (request_id != data->client.request_id) {
                    DEBUG_LOG(DBG_PARSER, p, "Request id not match=%d,%d\n", request_id, data->client.request_id);
                    dpi_fire_parser(p);
                    return;
                }
                dpi_finalize_parser(p);
                dpi_ignore_parser(p);
            } else {
                    DEBUG_LOG(DBG_PARSER, p, "No request before response message\n");
                    dpi_fire_parser(p);
                    return;
            }
            break;
        case 5: // RpcFailure;
            if (len < 8) return;
            request_id = be64toh(*(uint64_t *)(ptr));
            if (data->client_request){
                if (request_id != data->client.request_id) {
                    DEBUG_LOG(DBG_PARSER, p, "First spark request id not match\n");
                    dpi_fire_parser(p);
                    return;
                }
                dpi_finalize_parser(p);
                dpi_ignore_parser(p);
            } else {
                    DEBUG_LOG(DBG_PARSER, p, "No spark request before response message\n");
                    dpi_fire_parser(p);
                    return;
            }
            break;
        case 6: // StreamRequest;
            if (len < 4) return;
            str_len = ntohl(*(uint32_t *)(ptr));
            if (str_len > NIO_BUFFER_LIMIT || str_len > size) {
                DEBUG_LOG(DBG_PARSER, p, "Spark size mismatch,size=%d str_len=%d\n", size, str_len);
                dpi_fire_parser(p);
                return;
            }
            data->client_request = true;
            break;
        case 7: // StreamResponse;
        case 8: // StreamFailure;
            if (len < 4) return;
            str_len = ntohl(*(uint32_t *)(ptr));
            if (str_len > NIO_BUFFER_LIMIT || str_len > size) {
                DEBUG_LOG(DBG_PARSER, p, "Spark size mismatch,size=%d str_len=%d\n", size, str_len);
                dpi_fire_parser(p);
                return;
            }
            if (data->client_request) {
                dpi_finalize_parser(p);
                dpi_ignore_parser(p);
            } else {
                DEBUG_LOG(DBG_PARSER, p, "No stream request before response\n");
                dpi_fire_parser(p);
                return;
            }
            break;
        case 9: // OneWayMessage;       
            if (len < 4) return;
            DEBUG_LOG(DBG_PARSER, p, "Spark oneway message\n");
            msg_len = ntohl(*(uint32_t *)(ptr));
            if (msg_len > NIO_BUFFER_LIMIT || (msg_len+MESSAGE_ONEWAY_HEADER_LEN) != size) {
                DEBUG_LOG(DBG_PARSER, p, "Spark size mismatch,size=%d msg_len=%d\n", size, msg_len);
                dpi_fire_parser(p);
                return;
            }
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            return;
        default:
            DEBUG_LOG(DBG_PARSER, p, "Unknown message type=%d\n", msg_type);
            dpi_fire_parser(p);
            break;
    }

    dpi_set_asm_seq(p, w->seq+len);
    w->seq = w->seq + len;
}

static void spark_midstream(dpi_packet_t *p)
{
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    ptr = dpi_pkt_ptr(p);
    len = dpi_pkt_len(p);

    if (len >= MESSAGE_ONEWAY_HEADER_LEN) {
        uint64_t size = be64toh(*(uint64_t *)(ptr));
        if (size > NIO_BUFFER_LIMIT) {
                goto Exit;
        }
        int8_t  msg_type = ptr[8];
        ptr += 9;
        if (msg_type == 9) {
            uint32_t msg_len = ntohl(*(uint32_t *)(ptr));
            if (msg_len > NIO_BUFFER_LIMIT || (msg_len+MESSAGE_ONEWAY_HEADER_LEN) != size) {
                dpi_fire_parser(p);
                return;
            }
            DEBUG_LOG(DBG_PARSER, p, "Spark mid stream oneway message\n");
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            return;
        }
    }

Exit:
    dpi_fire_parser(p);
}

static void spark_new_session(dpi_packet_t *p)
{
    if (p->session->server.port >= 1024) {
        dpi_hire_parser(p);
    }
}

static void spark_new_mid_sess(dpi_packet_t *p)
{
    if (p->sport >= 1024 && p->sport >= 1024) {
        dpi_hire_parser(p);
    }
}

static void spark_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_spark = {
    .new_session = spark_new_session,
    .delete_data = spark_delete_data,
    .parser = spark_parser,
    .new_mid_sess = spark_new_mid_sess,
    .midstream = spark_midstream,
    .name = "spark",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_SPARK,
};

dpi_parser_t *dpi_spark_parser(void)
{
    return &dpi_parser_spark;
}


