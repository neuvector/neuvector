#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define TDS_PORT_LOW 1433
#define TDS_PORT_HIGH 2433
#define TDS_HDR_LEN 8
#define TDS_PKT_LEN_MAX (10*1024)

#define TDS4 0x04
#define TDS5 0x05
#define TDSVER70 0x70
#define TDSVER71 0x71
#define TDSVER72 0x72
#define TDS32VER70_WORD 0x00000070
#define TDS32VER71_WORD 0x01000071
#define TDS32VER72_WORD 0x02000972
#define TDS4_MIN_LOGIN_LEN 467
#define TDS4_MAJ_VER_OFFSET 466
#define TDS4_LOGIN_HOSTNAME_LEN_OFFSET 38
#define TDS4_LOGIN_HOSTNAME_LEN 30
#define TDS4_LOGIN_USERNAME_LEN_OFFSET 69
#define TDS4_LOGIN_USERNAME_LEN 30
#define TDS4_LOGIN_PASSWD_LEN_OFFSET 100
#define TDS4_LOGIN_PASSWD_LEN 30

#define TDS7_MIN_LOGIN_LEN 16
#define TDS7_MAJ_VER_OFFSET 15

#define TDS_LOGIN_VERSION_OFFSET 4
#define TDS7_LOGIN_CLIENT_OFFSET 36
#define TDS7_LOGIN_HOSTNAME_OFFSET 86 

#define TDS_RES_TOKEN_ERROR_MSG 0xAA  


#define TDS_ZERO_PKT 0
#define TDS_QUERY_PKT 1
#define TDS_LOGIN_PKT 2
#define TDS_RPC_PKT 3
#define TDS_RESP_PKT 4
#define TDS_RAW_PKT 5
#define TDS_ATTENTION_PKT 6
#define TDS_BULK_DATA_PKT 7
#define TDS_OPEN_CHN_PKT 8
#define TDS_CLOSE_CHN_PKT 9
#define TDS_RES_ERROR_PKT 10
#define TDS_LOG_CHN_ACK_PKT 11
#define TDS_ECHO_PKT 12
#define TDS_LOGOUT_CHN_PKT 13
#define TDS_TRANS_MGR_PKT 14
#define TDS_QUERY5_PKT 15
#define TDS_LOGIN7_PKT 16
#define TDS_SSPI_PKT 17
#define TDS_PRELOGIN_PKT 18
#define TDS_INVALID_PKT 19
#define TDS_TLS_PKT 23

#define is_valid_tds_type(x) (((x) >= TDS_QUERY_PKT && (x) < TDS_INVALID_PKT) || x == TDS_TLS_PKT)

/* The status field */
#define TDS_STATUS_NORMAL_PKT 0x00
#define TDS_STATUS_LAST_PKT 0x01
#define TDS_STATUS_IGNORE_EVENT 0x02
#define TDS_STATUS_EVENT_NOTIFICATION 0x04
#define TDS_STATUS_RESETCONNECTION 0x08
#define TDS_STATUS_RESETCONNECTIONSKIPTRAN 0x10

#define is_valid_tds_status(x) ((x) <= TDS_STATUS_EVENT_NOTIFICATION)

#define TDS_LANG_TOKEN 33  /*TDS 5.0 only*/

enum {
    TDS_PASS=0,
    TDS_NOTPASS
};

typedef struct tds_pkt_hdr_ {
    uint8_t type;
    uint8_t status;
    uint16_t length;
    uint16_t spid;
    uint8_t pktid;
    uint8_t window;
}tds_pkt_hdr_t;

typedef struct tds_wing_ {
    uint32_t seq;
} tds_wing_t;

typedef struct tds_data_ {
    tds_wing_t client, server;
} tds_data_t;

static const char* packet_type_names[] = {
    [TDS_ZERO_PKT] = "",
    [TDS_QUERY_PKT] = "SQL batch",
    [TDS_LOGIN_PKT] = "Pre-TDS7 login",
    [TDS_RPC_PKT] = "Remote Procedure Call",
    [TDS_RESP_PKT] = "Response",
    [TDS_RAW_PKT] = "Unused",
    [TDS_ATTENTION_PKT] = "Attention",
    [TDS_BULK_DATA_PKT] = "Bulk load data",
    [TDS_OPEN_CHN_PKT] = "Unused",
    [TDS_CLOSE_CHN_PKT] = "Unused",
    [TDS_RES_ERROR_PKT] = "Unused",
    [TDS_LOG_CHN_ACK_PKT] = "Unused",
    [TDS_ECHO_PKT] = "Unused",
    [TDS_LOGOUT_CHN_PKT] = "Unused",
    [TDS_TRANS_MGR_PKT] = "Transaction Manager Request",
    [TDS_QUERY5_PKT] = "TDS5 query",
    [TDS_LOGIN7_PKT] = "TDS7 login",
    [TDS_SSPI_PKT] = "SSPI message",
    [TDS_PRELOGIN_PKT] = "TDS7 pre-login message"
};

extern void check_sql_query(dpi_packet_t *p, uint8_t *query, int len, int app);

bool tds_port_is_in_range(uint16_t low, uint16_t high, uint16_t port)
{
    if (port >= low && port <= high) return true;
    return false;
}

static bool tds_quick_check(dpi_packet_t *p, uint8_t *ptr, uint32_t len, uint8_t type)
{
    uint32_t tds_major;

    if (type==TDS_LOGIN_PKT) {
        /* Use major version number to validate TDS 4/5 login packet */
        if (len < TDS4_MIN_LOGIN_LEN) {
            return false;
        }
        tds_major = *(ptr + TDS4_MAJ_VER_OFFSET);
        if (tds_major != TDS4 && tds_major != TDS5) {
            return false;
        }
    } else if (type==TDS_LOGIN7_PKT) {
        /* SQL Server 7 */
        if (len < TDS7_MIN_LOGIN_LEN) {
            return false;
        }
        tds_major = *(ptr + TDS7_MAJ_VER_OFFSET);
        if (tds_major != TDSVER70 && tds_major != TDSVER71 && tds_major != TDSVER72) {
            return false;
        }
    } else if (type==TDS_QUERY5_PKT) {
        if (len < 9) {
            return false;
        }
        /* if this is a TDS 5.0 query check the token */
        if (*(ptr + 8) != TDS_LANG_TOKEN) {
            return false;
        }
    } /*else if (!tds_port_is_in_range(TDS_PORT_LOW, TDS_PORT_HIGH, p->dport) &&
                !tds_port_is_in_range(TDS_PORT_LOW, TDS_PORT_HIGH, p->sport)) {
        return false;
    }*/
    return true;
}

/* tds 4.2&5, pre mssql server 7*/
static bool tds_parse_login(dpi_packet_t *p, tds_pkt_hdr_t *tds_pkt_hdr, uint8_t *ptr)
{
    uint8_t tlen;

    if (tds_pkt_hdr && tds_pkt_hdr->status != TDS_STATUS_NORMAL_PKT) {
        return false;
    }
    tlen = *(uint8_t *)(ptr + TDS4_LOGIN_HOSTNAME_LEN_OFFSET);
    if (tlen > TDS4_LOGIN_HOSTNAME_LEN){
        return false;
    }

    tlen = *(uint8_t *)(ptr + TDS4_LOGIN_USERNAME_LEN_OFFSET);
    if (tlen > TDS4_LOGIN_USERNAME_LEN){
        return false;
    }

    if (*(ptr + TDS4_LOGIN_USERNAME_LEN_OFFSET + 1) == '\0') {
        DEBUG_LOG(DBG_PARSER, p, "%s: empty password\n", packet_type_names[TDS_LOGIN_PKT]);
        return false;
    }

    tlen = *(uint8_t *)(ptr + TDS4_LOGIN_PASSWD_LEN_OFFSET);
    if (tlen > TDS4_LOGIN_PASSWD_LEN) {
        return false;
    }

    return true;
}

static int tds_prelogin_detect_tls(dpi_packet_t *p, uint8_t *ptr, uint32_t len, bool parsedhdr)
{
    uint8_t tls_type, tls_maj_ver, tls_min_ver;
    uint16_t tls_len;

    tls_type = *(uint8_t *)ptr;
    tls_maj_ver = *(uint8_t *)(ptr + 1);
    tls_min_ver = *(uint8_t *)(ptr + 2);
    tls_len = ntohs(*(uint16_t *)(ptr + 3));
    if((tls_type >= 0x14) && (tls_type <= 0x18) &&
        (tls_maj_ver == 3) && (tls_min_ver <= 3) &&
        ((tls_len + 5 <= len - (parsedhdr ? TDS_HDR_LEN : 0)))){
        return 1;
    }
    return 0;
}

static bool tds_parse_prelogin7(dpi_packet_t *p, uint8_t *ptr, uint32_t len)
{
    uint8_t token;
    uint16_t tokenlen = 0;
    uint32_t remaining_len = len - TDS_HDR_LEN;
    uint8_t *data_ptr = NULL;
    if(tds_prelogin_detect_tls(p, ptr+TDS_HDR_LEN, len, true))
    {
        /*
         * We consider it to be a true tds packet, 
         * If tls exchange is detected in a tds 
         * prelogin packet.
         */
        DEBUG_LOG(DBG_PARSER, p, "tds prelogin tls exchange\n");
        return true;
    }

    data_ptr = ptr + TDS_HDR_LEN;
    while(remaining_len > 0)
    {
        token = *(data_ptr);
        if(token == 0xff) {
            remaining_len -= 1;
            break;
        }
        if (remaining_len < 5) {
            return false;//malformatted tds prelogin7 packet
        }
        data_ptr += 3;
        tokenlen += ntohs(*(uint16_t *)data_ptr);
        data_ptr += 2;
        remaining_len -= 5;
    }

    DEBUG_LOG(DBG_PARSER, p, "tds prelogin remaining length(%u), tokenlen(%hu)\n", remaining_len, tokenlen);
    if (remaining_len < 0) {
        return false;
    }

    //remaining length should be == tokenlen
    return (remaining_len <= tokenlen);
}

static bool tds_parse_login7(dpi_packet_t *p, uint8_t *ptr, uint32_t len)
{
    uint8_t *tds_login7_start = ptr + TDS_HDR_LEN;
    uint8_t *tds_login7_ptr;
    uint32_t tds_ver;
    uint16_t offset, prev_offset, tlen;
    int i;

    tds_login7_ptr = tds_login7_start + TDS_LOGIN_VERSION_OFFSET;
    tds_ver = GET_BIG_INT32(tds_login7_ptr);
    if (tds_ver != TDS32VER70_WORD && 
        tds_ver != TDS32VER71_WORD && 
        tds_ver != TDS32VER72_WORD) {
        return false;
    }

    //hostname offset and length
    tds_login7_ptr = tds_login7_start + TDS7_LOGIN_CLIENT_OFFSET;
    offset = GET_LITTLE_INT16(tds_login7_ptr);
    tds_login7_ptr += 2;
    tlen = GET_LITTLE_INT16(tds_login7_ptr);

    prev_offset = offset;

    // username offset and length
    tds_login7_ptr += 2;
    offset = GET_LITTLE_INT16(tds_login7_ptr);
    if (offset == 0) {
        tds_login7_ptr += 6; 
        goto morecheck;
    } else if (offset != prev_offset + (tlen << 1)) {
        DEBUG_LOG(DBG_PARSER, p, "TDS: login7 malformat username offset\n");
        return false;
    }
    tds_login7_ptr += 2; 
    tlen = GET_LITTLE_INT16(tds_login7_ptr);

    prev_offset = offset;

    // password offset and length
    tds_login7_ptr += 2;
    offset = GET_LITTLE_INT16(tds_login7_ptr);
    if (offset == 0) {
        tds_login7_ptr += 2; 
        goto morecheck;
    } else if (offset != prev_offset + (tlen << 1)) {
        DEBUG_LOG(DBG_PARSER, p, "TDS: login7 malformat password offset\n");
        return false;
    }
    tds_login7_ptr += 2; 
    tlen = GET_LITTLE_INT16(tds_login7_ptr);
    if (tlen == 0) {
        DEBUG_LOG(DBG_PARSER, p, "TDS: login7 empty password\n");
    }

    prev_offset = offset;

morecheck:
    // check app and server name
    for (i = 0; i < 2; i++) {
        tds_login7_ptr += 2;
        offset = GET_LITTLE_INT16(tds_login7_ptr);
        if (offset == 0) {
            tds_login7_ptr += 2;
            continue;
        } else if (offset != prev_offset + (tlen << 1)) {
            DEBUG_LOG(DBG_PARSER, p, "TDS: login7 malformat app/server offset\n");
            return false;
        }
        tds_login7_ptr += 2; 
        tlen = GET_LITTLE_INT16(tds_login7_ptr);

        prev_offset = offset;
    }

    return true;
}

static bool tds_parse_query(dpi_packet_t *p, uint8_t* ptr, uint32_t len) 
{
    tds_pkt_hdr_t* tds_pkt_hdr = (tds_pkt_hdr_t*)ptr;
    uint16_t tds_pkt_len = 0;
    uint8_t *tds_query_ptr = ptr + TDS_HDR_LEN;
    uint32_t tds_query_len = len - TDS_HDR_LEN;
    uint16_t pos = 0;
    uint16_t start = 0;
    int idx = 0;
    int cnt = 0;
    uint8_t slct[tds_query_len];

    tds_pkt_len = ntohs(tds_pkt_hdr->length);
    if (tds_pkt_len != len) {
        DEBUG_LOG(DBG_PARSER, p, "misformatted tds query packet\n");
        return false;
    }

    while (pos < tds_query_len) {
        switch (*(tds_query_ptr + pos)) {
            case 'S':
            case 's':
            case 'I':
            case 'i':
                if (tds_query_len - pos > 12) {
                    cnt = 0;
                    idx = 0;
                    start = pos;
                    while (idx < 12) {
                        if(!(idx&1)) {
                            slct[cnt++]=*(tds_query_ptr + pos);
                        }
                        idx++;
                        pos++;
                    }
                    slct[cnt] = '\0';
                    if (strncasecmp((char *)slct,"SELECT", 6) == 0 || 
                        strncasecmp((char *)slct,"INSERT", 6) == 0) {
                        //forward to end of query packet
                        idx = 0;
                        while (pos < tds_query_len) {
                            if(!(idx&1)) {
                                slct[cnt++] = *(tds_query_ptr + pos);
                            }
                            idx++;
                            pos++;
                        }
                        slct[cnt]='\0';
                        DEBUG_LOG(DBG_PARSER, p, "TDS: cnt(%d), select string(%s)\n", cnt,(char *)slct);
                        strlcpy((char *)p->decoded_pkt.ptr, (char *)slct, cnt);
                        p->decoded_pkt.seq = dpi_pkt_seq(p) + (tds_query_ptr + start - ptr);
                        p->decoded_pkt.len = cnt;
                        if (strncasecmp((char *)slct,"SELECT", 6) == 0){
                            p->dlp_area[DPI_SIG_CONTEXT_TYPE_SQL_QUERY].dlp_start = dpi_pkt_seq(p) + (tds_query_ptr + start - ptr);
                            p->dlp_area[DPI_SIG_CONTEXT_TYPE_SQL_QUERY].dlp_end = p->dlp_area[DPI_SIG_CONTEXT_TYPE_SQL_QUERY].dlp_start + cnt;
                        }
                        //embedded sql injection threat detection
                        check_sql_query(p, slct, cnt, DPI_APP_TDS);
                    }
                }
                break;
            default:
                break;
        }
        if (pos < tds_query_len) {
            pos++;
        }
    }

    DEBUG_LOG(DBG_PARSER, p, "TDS: query final len(%d), original len(%d)\n", pos + TDS_HDR_LEN, len);
    return true;
}
static bool tds_normalize_response(dpi_packet_t *p, uint8_t* ptr, uint32_t len) 
{
    tds_pkt_hdr_t* tds_pkt_hdr = (tds_pkt_hdr_t*)ptr;
    uint16_t tds_pkt_len = 0;
    uint8_t *tds_resp_ptr = ptr + TDS_HDR_LEN;
    uint32_t tds_resp_len = len - TDS_HDR_LEN;
    uint16_t pos = 0;
    uint16_t start = pos;
    int cnt = 0;
    uint8_t rsp[tds_resp_len];

    tds_pkt_len = ntohs(tds_pkt_hdr->length);
    if (tds_pkt_len != len) {
        DEBUG_LOG(DBG_PARSER, p, "misformatted tds query packet\n");
        return false;
    }
    while (pos < tds_resp_len) {
        if(*(tds_resp_ptr + pos) != '\0') {
            rsp[cnt++] = *(tds_resp_ptr + pos);
        }
        if (pos < tds_resp_len) {
            pos++;
        }
    }
    rsp[cnt]='\0';
    DEBUG_LOG(DBG_PARSER, p, "TDS: cnt(%d), normalized response packet data(%s)\n", cnt,(char *)rsp);
    strlcpy((char *)p->decoded_pkt.ptr, (char *)rsp, cnt);
    p->decoded_pkt.seq = dpi_pkt_seq(p) + (tds_resp_ptr + start - ptr);
    p->decoded_pkt.len = cnt;

    DEBUG_LOG(DBG_PARSER, p, "TDS: response final len(%d), original len(%d)\n", pos + TDS_HDR_LEN, len);
    return true;
}

static void tds_parser(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    tds_data_t *data;
    tds_wing_t *w;
    uint8_t *ptr;
    uint32_t len;
    tds_pkt_hdr_t* tds_pkt_hdr = NULL;
    uint8_t tds_pkt_type;
    uint8_t tds_pkt_status;
    uint16_t tds_pkt_len = 0;
    int rc = TDS_NOTPASS;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not TDS, First packet from server\n");
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }

        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;

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

    if (len < TDS_HDR_LEN) {
        /*not enough length to hold tds header*/
        dpi_fire_parser(p);
        return;
    }

    while (len > TDS_HDR_LEN) {
        /*it is possible the payload is encrypted*/
        if(tds_prelogin_detect_tls(p,ptr,len, false))
        {
            /*skip the encrypted packet*/
            DEBUG_LOG(DBG_PARSER, p, "tds tls exchange\n");
            ptr += len;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);
            return;
        }

        tds_pkt_hdr = (tds_pkt_hdr_t*)ptr;
        tds_pkt_type = tds_pkt_hdr->type;
        if (!is_valid_tds_type(tds_pkt_type)) {
            /*unknown tds packet type*/
            DEBUG_LOG(DBG_PARSER, p, "Unknown tds packet type(%d)\n", tds_pkt_type);
            dpi_fire_parser(p);
            return;
        }

        tds_pkt_status = tds_pkt_hdr->status;
        if (!is_valid_tds_status(tds_pkt_status)) {
            /*invalid tds packet status*/
            DEBUG_LOG(DBG_PARSER, p, "Unknown tds packet status(%d)\n", tds_pkt_status);
            dpi_fire_parser(p);
            return;
        }

        tds_pkt_len = ntohs(tds_pkt_hdr->length);
        DEBUG_LOG(DBG_PARSER, p, "TDS pkt length (%hu), len(%u)\n", tds_pkt_len, len);

        if (tds_pkt_len < TDS_HDR_LEN) {
            DEBUG_LOG(DBG_PARSER, p, "TDS packet length(%d) is less than the header length(8)\n", tds_pkt_len);
            dpi_fire_parser(p);
            return;
        }

        /*
         * tds packet can be accross serveral 
         * packets, we do not move p->parser_asm_seq
         * until all the PDUs got assembled.
         */
        if (tds_pkt_len > len) {
            if (tds_pkt_len > TDS_PKT_LEN_MAX) {
                /* abnormal tds pktlen */
                dpi_fire_parser(p);
                return;
            }
            return;
        }

        if (!tds_quick_check(p, ptr, len, tds_pkt_type)){
            DEBUG_LOG(DBG_PARSER, p, "TDS: failed tds quick check\n");
            dpi_fire_parser(p);
            return;
        }

        DEBUG_LOG(DBG_PARSER, p, "tds: %s packet\n", packet_type_names[tds_pkt_hdr->type]);
        switch (tds_pkt_hdr->type) {
            case TDS_PRELOGIN_PKT:
                if (!tds_parse_prelogin7(p,ptr,tds_pkt_len)) {
                    DEBUG_LOG(DBG_PARSER, p, "TDS: failed %s check\n", packet_type_names[tds_pkt_hdr->type]);
                    dpi_fire_parser(p);
                    return;
                }
                rc = TDS_PASS;
                break;
            case TDS_LOGIN_PKT:
                if (!tds_parse_login(p, tds_pkt_hdr, ptr)){
                    DEBUG_LOG(DBG_PARSER, p, "TDS: failed %s check\n", packet_type_names[tds_pkt_hdr->type]);
                    dpi_fire_parser(p);
                    return;
                }
                rc = TDS_PASS;
                break;
            case TDS_LOGIN7_PKT:
                if (!tds_parse_login7(p, ptr, len)){
                    DEBUG_LOG(DBG_PARSER, p, "TDS: failed %s check\n", packet_type_names[tds_pkt_hdr->type]);
                    dpi_fire_parser(p);
                    return;
                }
                rc = TDS_PASS;
                break;
            case TDS_QUERY_PKT:
                if (!tds_parse_query(p, ptr, tds_pkt_len)){
                    DEBUG_LOG(DBG_PARSER, p, "TDS: failed %s check\n", packet_type_names[tds_pkt_hdr->type]);
                    dpi_fire_parser(p);
                    return;
                }
                rc = TDS_PASS;
                break;
            case TDS_RESP_PKT:
                if (!tds_normalize_response(p, ptr, tds_pkt_len)){
                    DEBUG_LOG(DBG_PARSER, p, "TDS: failed %s check\n", packet_type_names[tds_pkt_hdr->type]);
                    dpi_fire_parser(p);
                    return;
                }
                rc = TDS_PASS;
                break;
            case TDS_RPC_PKT:
            case TDS_QUERY5_PKT:
            case TDS_SSPI_PKT:
            case TDS_ATTENTION_PKT:
            case TDS_BULK_DATA_PKT:
            case TDS_OPEN_CHN_PKT:
            case TDS_TRANS_MGR_PKT://
            case TDS_RAW_PKT:
            case TDS_CLOSE_CHN_PKT:
            case TDS_RES_ERROR_PKT:
            case TDS_LOG_CHN_ACK_PKT: 
            case TDS_ECHO_PKT:
            case TDS_LOGOUT_CHN_PKT:
                if (dpi_is_parser_final(p)) {
                    rc = TDS_PASS;
                    DEBUG_LOG(DBG_PARSER, p, "TDS: type(%d)\n", tds_pkt_hdr->type);
                    break;
                } else {
                    DEBUG_LOG(DBG_PARSER, p, "TDS: not type(%d)\n", tds_pkt_hdr->type);
                    dpi_fire_parser(p);
                    return;
                }
            default:
                rc = TDS_NOTPASS;
                break;
        }
        ptr += tds_pkt_len;
        len -= tds_pkt_len;
        w->seq = dpi_ptr_2_seq(p, ptr);
        dpi_set_asm_seq(p, w->seq);
    }

    if (len > 0) {
        dpi_fire_parser(p);
    }

    if (!dpi_is_parser_final(p) && rc == TDS_PASS) {
        dpi_finalize_parser(p);
        //dpi_ignore_parser(p);
    }
}

static void tds_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void tds_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_tds = {
    .new_session = tds_new_session,
    .delete_data = tds_delete_data,
    .parser = tds_parser,
    .name = "tds",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_TDS,
};

dpi_parser_t *dpi_tds_tcp_parser(void)
{
    return &dpi_parser_tds;
}

