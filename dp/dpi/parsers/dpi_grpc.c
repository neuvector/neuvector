#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define HTTP2_FRAME_HEADER_LENGTH 9
#define HTTP2_MAGIC_FRAME_LENGTH 24

/* Header Type Code */
#define HTTP2_DATA          0
#define HTTP2_HEADERS       1
#define HTTP2_PRIORITY      2
#define HTTP2_RST_STREAM    3
#define HTTP2_SETTINGS      4
#define HTTP2_PUSH_PROMISE  5
#define HTTP2_PING          6
#define HTTP2_GOAWAY        7
#define HTTP2_WINDOW_UPDATE 8
#define HTTP2_CONTINUATION  9
#define HTTP2_ALTSVC        0xA
#define HTTP2_BLOCKED       0xB

#define HTTP2_SETTING_SENT 0x01
#define HTTP2_SETTING_ACKED 0x02

/* Flags */
#define HTTP2_FLAGS_ACK 0x01 /* for SETTINGS */

#define HTTP2_HEADER_CONTENT_TYPE "content-type"/*12 bytes*/
#define HTTP2_HDR_CONT_TYPE_LEN 12
#define HTTP2_HEADER_APP_GRPC "application/grpc"/*16 bytes*/
#define HTTP2_HDR_APP_GRPC_LEN 16
#define HTTP2_GRPC_CONTYPE_LEN 36 /*4+12+4+16=36 bytes*/

#define HTTP2_LEN_MAX (10*1024)

/* Magic Header : PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n */
static uint8_t http2clientmagic[] = {
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
    0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
};

static const char* http2_type_vals[] = {
    [HTTP2_DATA] = "DATA",
    [HTTP2_HEADERS] = "HEADERS",
    [HTTP2_PRIORITY] = "PRIORITY",
    [HTTP2_RST_STREAM] = "RST_STREAM",
    [HTTP2_SETTINGS] = "SETTINGS",
    [HTTP2_PUSH_PROMISE] = "PUSH_PROMISE",
    [HTTP2_PING] = "PING",
    [HTTP2_GOAWAY] = "GOAWAY",
    [HTTP2_WINDOW_UPDATE] = "WINDOW_UPDATE",
    [HTTP2_CONTINUATION] = "CONTINUATION",
    [HTTP2_ALTSVC] = "ALTSVC",
    [HTTP2_BLOCKED] = "BLOCKED",
};

typedef struct grpc_wing_ {
    uint32_t seq;
    uint32_t h2_strm_hdr_cnt;
    uint32_t pktcnt;
    uint8_t setting_flag;
} grpc_wing_t;

typedef struct grpc_data_ {
    grpc_wing_t client, server;
    bool isgrpc;
} grpc_data_t;

static bool grpc_find_grpc_content_type(dpi_packet_t *p, uint8_t *ptr, uint32_t hdrstrmlen)
{
    uint32_t pos = 0;

    DEBUG_LOG(DBG_PARSER, p, "c2s stream length(%u)\n", hdrstrmlen);

    while (pos < hdrstrmlen) {
        switch (*(ptr + pos)) {
            case '@':
                pos += 2;
                if ((hdrstrmlen - pos > HTTP2_HDR_CONT_TYPE_LEN) && 
                    (*(ptr + pos) == 'c' || *(ptr + pos) == 'C') &&
                    strncasecmp((char *)(ptr + pos),
                    HTTP2_HEADER_CONTENT_TYPE, HTTP2_HDR_CONT_TYPE_LEN) == 0) {
                    pos += HTTP2_HDR_CONT_TYPE_LEN;
                    pos += 1;//name/value separator
                    if((hdrstrmlen - pos > HTTP2_HDR_APP_GRPC_LEN) &&  
                        (*(ptr + pos) == 'a' || *(ptr + pos) == 'A') &&
                        strncasecmp((char *)(ptr + pos),
                        HTTP2_HEADER_APP_GRPC, HTTP2_HDR_APP_GRPC_LEN) == 0){
                        DEBUG_LOG(DBG_PARSER, p, "c2s application/grpc found\n");
                        return true;
                    }
                }
                break;
            default:
                break;
        }
        pos++;
    }
    return false;
}

static void grpc_parser(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    grpc_data_t *data;
    grpc_wing_t *w;
    uint8_t *ptr;
    uint32_t len;
    uint32_t h2_hdr_len = 0;
    uint32_t h2_strm_len = 0;
    uint8_t h2_strm_type = 0;
    uint8_t h2_strm_flags = 0;
    
    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }

        data->client.seq = s->client.init_seq;
        data->client.setting_flag = 0;
        data->client.h2_strm_hdr_cnt = 0;
        data->client.pktcnt = 0;
        data->server.seq = s->server.init_seq;
        data->server.setting_flag = 0;
        data->server.h2_strm_hdr_cnt = 0;
        data->server.pktcnt = 0;
        data->isgrpc = false;

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

    /*
     * There is not enough space to hold http2 frame 
     * header or initial c2s magic frame sequences
     */
    if (len < HTTP2_FRAME_HEADER_LENGTH ||
        (dpi_is_client_pkt(p) && 
         data->client.h2_strm_hdr_cnt == 0 && 
         len < HTTP2_MAGIC_FRAME_LENGTH)) {
        dpi_fire_parser(p);
        return;
    }

    while (len >= HTTP2_FRAME_HEADER_LENGTH) {
        if (dpi_is_client_pkt(p) &&
            data->client.h2_strm_hdr_cnt == 0 &&
            memcmp(ptr, http2clientmagic, HTTP2_MAGIC_FRAME_LENGTH) != 0){
            dpi_fire_parser(p);
            return;
        }

        if (dpi_is_client_pkt(p) &&
            data->client.h2_strm_hdr_cnt == 0) {
            h2_hdr_len = 0;
            h2_strm_len = HTTP2_MAGIC_FRAME_LENGTH;
            DEBUG_LOG(DBG_PARSER, p, "c2s magic sent\n");
        } else {
            h2_hdr_len = HTTP2_FRAME_HEADER_LENGTH;
            h2_strm_len = GET_BIG_INT24(ptr);
            ptr += 3;
            h2_strm_type = *ptr;
            ptr += 1;
            h2_strm_flags = *ptr;
            ptr += 5;
        }
        DEBUG_LOG(DBG_PARSER, p, "%s http2 pkt len(%u) header len(%u), stream len(%u), type(%s), flag(0x%02x), stream cnt(%u)\n", 
                  dpi_is_client_pkt(p) ? "c2s" : "s2c", len, h2_hdr_len, h2_strm_len, 
                  h2_strm_type > HTTP2_BLOCKED ? "unknown type" : http2_type_vals[h2_strm_type], 
                  h2_strm_flags, dpi_is_client_pkt(p) ? data->client.h2_strm_hdr_cnt : data->server.h2_strm_hdr_cnt);

        /* tcp segmentation */
        if (h2_hdr_len + h2_strm_len > len) {
            if (h2_hdr_len + h2_strm_len > HTTP2_LEN_MAX) {
                /* abnormal http2 length */
                dpi_fire_parser(p);
                return;
            }
            return;
        }
        if (dpi_is_client_pkt(p)){ 
            if (data->client.h2_strm_hdr_cnt == 1) {
                if (h2_strm_type != HTTP2_SETTINGS) {
                    /*
                     * In http2 preface, a HTTP2 SETTING should 
                     * immediately follow magic.
                     */
                    dpi_fire_parser(p);
                    return;
                }
                data->client.setting_flag |= HTTP2_SETTING_SENT;
                DEBUG_LOG(DBG_PARSER, p, "c2s HTTP2_SETTING_SENT\n");
            } else if (data->client.h2_strm_hdr_cnt != 0){
                if ((h2_strm_type == HTTP2_SETTINGS) && (h2_strm_flags & HTTP2_FLAGS_ACK) && 
                    !(data->server.setting_flag & HTTP2_SETTING_ACKED)) {
                    data->server.setting_flag |= HTTP2_SETTING_ACKED;
                    DEBUG_LOG(DBG_PARSER, p, "c2s server HTTP2_SETTING_ACKED\n");
                }

                if (h2_strm_type == HTTP2_HEADERS) {
                    if (!data->isgrpc) {
                        data->isgrpc = grpc_find_grpc_content_type(p, ptr, h2_strm_len);
                    }
                }
            }
            data->client.h2_strm_hdr_cnt++;
        } else {//s2c
            if (data->server.h2_strm_hdr_cnt == 0) { 
                if (h2_strm_type != HTTP2_SETTINGS) {
                    /*
                     * In http2 preface, a HTTP2 SETTING should 
                     * be first packet from server.
                     */
                    dpi_fire_parser(p);
                    return;
                }
                data->server.setting_flag |= HTTP2_SETTING_SENT;
                DEBUG_LOG(DBG_PARSER, p, "s2c server HTTP2_SETTING_SENT\n");
            } else {
                if (!(data->client.setting_flag & HTTP2_SETTING_ACKED) && 
                    h2_strm_type == HTTP2_SETTINGS && (h2_strm_flags & HTTP2_FLAGS_ACK)){
                    data->client.setting_flag |= HTTP2_SETTING_ACKED;
                    DEBUG_LOG(DBG_PARSER, p, "s2c client HTTP2_SETTING_ACKED\n");
                }
            }
            data->server.h2_strm_hdr_cnt++;
        }
        ptr += h2_strm_len;
        len -= (h2_strm_len+h2_hdr_len);
        w->seq = dpi_ptr_2_seq(p, ptr);
        dpi_set_asm_seq(p, w->seq);
    }

    if (dpi_is_client_pkt(p)) {
        data->client.pktcnt++;
        DEBUG_LOG(DBG_PARSER, p, "c2s pktcnt(%u)\n", data->client.pktcnt);
    } else {
        data->server.pktcnt++;
        DEBUG_LOG(DBG_PARSER, p, "s2c pktcnt(%u)\n", data->server.pktcnt);
    }
    /*HTTP2 preface fail*/
    if (!(data->client.setting_flag & HTTP2_SETTING_ACKED) && 
        data->server.pktcnt >= 2) {
        dpi_fire_parser(p);
        return;
    }
    /*HTTP2 preface fail*/
    if (!(data->server.setting_flag & HTTP2_SETTING_ACKED) && 
        data->client.pktcnt >= 2) {
        dpi_fire_parser(p);
        return;
    }
    if ((data->client.setting_flag & HTTP2_SETTING_ACKED) && 
        (data->server.setting_flag & HTTP2_SETTING_ACKED) && 
        data->isgrpc) {
        DEBUG_LOG(DBG_PARSER, p, "HTTP2 PREFACE ESTABLISHED, GRPC IDENTIFIED\n");
        dpi_finalize_parser(p);
        dpi_ignore_parser(p);
    }
}

static void grpc_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void grpc_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_grpc = {
    .new_session = grpc_new_session,
    .delete_data = grpc_delete_data,
    .parser = grpc_parser,
    .name = "grpc",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_GRPC,
};

dpi_parser_t *dpi_grpc_tcp_parser(void)
{
    return &dpi_parser_grpc;
}

