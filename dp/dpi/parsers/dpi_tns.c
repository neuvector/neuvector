#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define TNS_HDR_LEN 8
#define TNS_CONNECT_LEN_MIN 42
#define TNS_ACCEPT_LEN_MIN 24
#define TNS_REDIR_LEN_MIN 2
#define TNS_DATA_LEN_MIN 2
#define TNS_PORT_MAX 65535
#define TNS_FLD_LEN 128
#define TNS_PKT_LEN_MAX (10*1024)
#define TNS_DATAID_SQL_USER_OCI 0x03
#define TNS_DATAID_SQL_USER_ROP 0x08 /*Return OPI Parameter*/
#define TNS_DATA_CALLID_BEC 0x5E /*Bundled Execution Call*/
#define TNS_DATA_CALLID_GAC 0x73 /*Generic Authentication Call*/
#define TNS_DATAID_SQL_PIGGYBACK 0x11
#define TNS_DATA_CALLID_CCC 0x69 /*Cursor Close Call*/
#define TNS_DATA_CALLID_SSP 0x6b /*Session switching piggyback (V8)*/

#define SKIP_GROUP()  \
    while ( pos < tnsdata_len-1 && *(tnsbodyptr+pos) != ')') { \
        pos++; \
    }

#define CONTINUE_ON_GROUP()  \
    while ( pos < tnsdata_len-1 && (*(tnsbodyptr+pos) == ' ' || *(tnsbodyptr+pos) == '=')) { \
        pos++; \
    }

#define END_OF_PARAM()  \
    while (pos < tnsdata_len-1 && *(tnsbodyptr+pos) != '(') { \
        pos++; \
    } 

#define SKIP_TO_END_OF_SELECT()  \
    while ( pos < tnsdata_len-1 && \
            *(tnsbodyptr+pos) != 0x01 && \
            *(tnsbodyptr + pos) != 0x00 ) { \
        pos++; \
    }

enum {
    /*
     * TNS Packet Types, value 8 and 10 
     * are undefined
    */
    TNS_TYPE_CONNECT=1,
    TNS_TYPE_ACCEPT,
    TNS_TYPE_ACK,
    TNS_TYPE_REFUSE,
    TNS_TYPE_REDIRECT,
    TNS_TYPE_DATA,
    TNS_TYPE_NULL=7,
    TNS_TYPE_ABORT=9,
    TNS_TYPE_RESEND=11,
    TNS_TYPE_MARKER,
    TNS_TYPE_ATTENTION,
    TNS_TYPE_CONTROL,
    TNS_TYPE_MAX
};

enum {
    TNS_PASS=0,
    TNS_NOTPASS
};

typedef struct tns_header_ {
    uint16_t pktlen;
    uint16_t pktchksm;
    uint8_t  pkttype;
    uint8_t  rsrvd;
    uint16_t hdrchksm;
} tns_header_t;

typedef struct tns_wing_ {
    uint32_t seq;
} tns_wing_t;

typedef struct tns_data_ {
    tns_wing_t client, server;
} tns_data_t;

extern void check_sql_query(dpi_packet_t *p, uint8_t *query, int len, int app);

static uint16_t tns_connect_addr(dpi_packet_t *p, uint8_t *tnsbodyptr, uint16_t tnsdata_len, uint16_t pos, int *rc)
{
    uint16_t start;
    uint32_t port=0;
    char prtcl[TNS_FLD_LEN];
    char tnshost[TNS_FLD_LEN];

    while (pos < tnsdata_len && *(tnsbodyptr + pos) != ')') {
        switch (*(tnsbodyptr + pos)) {
            case 'P':
            case 'p':
                if (tnsdata_len - pos > 8 && strncasecmp((char *)(tnsbodyptr + pos + 1), "ROTOCOL", 7) == 0) {
                    pos += 8;
                    CONTINUE_ON_GROUP()
                    start = pos;

                    SKIP_GROUP()
                    strlcpy(prtcl, (char *)(tnsbodyptr + start), pos - start+1);

                    DEBUG_LOG(DBG_PARSER, p, "tns: connect: protocol (%s)\n",prtcl);

                } else if (tnsdata_len - pos > 4 && strncasecmp((char *)(tnsbodyptr + pos + 1), "ORT", 3) == 0) {
                    pos += 4;
                    CONTINUE_ON_GROUP()
                    start = pos;

                    SKIP_GROUP()
 
                    if ( pos - start > 0 && pos - start < 6) {
                        /* Validating of the port# */
                        port = strtoul((char *)(tnsbodyptr + start), 0, 10);
                        if (port > TNS_PORT_MAX) {
                            DEBUG_LOG(DBG_PARSER, p, "tns: connect: port (%u) > (%d)\n", port,TNS_PORT_MAX);
                            dpi_fire_parser(p);
                            *rc = TNS_NOTPASS;
                            return tnsdata_len;
                        }
                    } else {
                        if (pos - start > 0) {
                            char tmport[pos - start + 1];
                            strlcpy(tmport, (char *)(tnsbodyptr + start), pos - start + 1);
                            DEBUG_LOG(DBG_PARSER, p, "tns: connect: connect port (%s) abnormal \n", tmport);
                            dpi_fire_parser(p);
                            *rc = TNS_NOTPASS;
                            return tnsdata_len;
                        }
                    }

                    DEBUG_LOG(DBG_PARSER, p, "tns: connect: port (%u)\n", port);
                } else {
                    SKIP_GROUP()
                }
                break;
            case 'H':
            case 'h':
                if (tnsdata_len - pos > 4 && strncasecmp((char *)(tnsbodyptr + pos + 1), "OST", 3) == 0) {
                    pos += 4;
                    CONTINUE_ON_GROUP()
                    start = pos;

                    SKIP_GROUP()

                    strlcpy(tnshost, (char *)(tnsbodyptr + start), pos - start + 1);
                    DEBUG_LOG(DBG_PARSER, p, "tns: connect: host (%s) \n", tnshost);
                } else {
                    SKIP_GROUP()
                }
                break;
            default:
                if (isalpha(*(tnsbodyptr + pos))) {
                    SKIP_GROUP()
                }
        }
        pos++;
    }
    if ((strncasecmp(prtcl, "TCP", 3) == 0) && (port == 1521 || (port >= 1522 && port <= 1540))) {
        *rc = TNS_PASS;
    }
    return pos;
}

static uint32_t tns_connect(dpi_packet_t *p, uint8_t *ptr, uint32_t len, int *rc)
{
    uint8_t *tnsbodyptr = ptr + TNS_HDR_LEN;
    uint32_t tnsbody_len = len - TNS_HDR_LEN;
    uint16_t tnsdata_offset, tnsdata_len;
    uint16_t pos = 0;

    if (!dpi_is_client_pkt(p)) {
        DEBUG_LOG(DBG_PARSER, p, "tns: connect: packet not from client side\n");
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    }

    if (tnsbody_len < TNS_CONNECT_LEN_MIN) {
        DEBUG_LOG(DBG_PARSER, p, "tns: connect: body length (%u) is < (%d)\n", tnsbody_len, TNS_CONNECT_LEN_MIN);
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    } else {
        tnsdata_len = *(tnsbodyptr + 16);
        tnsdata_len <<= 8;
        tnsdata_len += *(tnsbodyptr + 17);

        tnsdata_offset = *(tnsbodyptr + 18);
        tnsdata_offset <<= 8;
        tnsdata_offset += *(tnsbodyptr + 19);

        DEBUG_LOG(DBG_PARSER, p, "tns: connect tns data len(%u) tns data offset(%u)\n", tnsdata_len, tnsdata_offset);

        tnsbodyptr = ptr + tnsdata_offset;
        if (tnsdata_offset + tnsdata_len > len) {
            DEBUG_LOG(DBG_PARSER, p, "tns: connect: abnormal connect data len(%hu).\n", tnsdata_len);
            dpi_fire_parser(p);
            *rc = TNS_NOTPASS;
            return len;
        } else {
            if ( tnsdata_len == 0) {
                *rc = TNS_PASS;
                return len;
            }

            while (pos < tnsdata_len) {
                if ((*(tnsbodyptr + pos) == 'D' || *(tnsbodyptr + pos) == 'd' )&& tnsdata_len - pos > 11) {
                    if (strncasecmp((char *)(tnsbodyptr + pos + 1), "ESCRIPTION", 10) != 0) {
                        DEBUG_LOG(DBG_PARSER, p, "tns: connect: no \"DESCRIPTION\" \n");
                        dpi_fire_parser(p);
                        *rc = TNS_NOTPASS;
                        return len;
                    } else {
                        pos += 11;
                        break;
                    }
                }
                pos++;
            }

            while (pos < tnsdata_len && *(tnsbodyptr + pos) != ')') {
                switch (*(tnsbodyptr + pos)) {
                    case 'A':
                    case 'a':
                        if (tnsdata_len - pos > 7 && strncasecmp((char *)(tnsbodyptr + pos + 1),
                            "DDRESS", 6) == 0) {
                            pos += 7;
                            pos = tns_connect_addr(p, tnsbodyptr, tnsdata_len, pos, rc);
                            END_OF_PARAM()
                        }
                        break;
                    default:
                        if (isalpha(*(tnsbodyptr + pos))) {
                            END_OF_PARAM()
                        }
                }
                pos++;
            }
        }
    }
    return pos + tnsdata_offset;
}

static uint32_t tns_accept(dpi_packet_t *p, uint8_t *ptr, uint32_t len, int *rc) {
    uint8_t *tnsbodyptr = ptr + TNS_HDR_LEN;
    uint32_t tnsbody_len = len - TNS_HDR_LEN;
    uint16_t tnsdata_offset, tnsdata_len;

    if (dpi_is_client_pkt(p)) {
        DEBUG_LOG(DBG_PARSER, p, "tns: accept: packet not from server side\n");
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    }

    if (tnsbody_len < TNS_ACCEPT_LEN_MIN) {
        DEBUG_LOG(DBG_PARSER, p, "tns: minimum accept data length is (%d)\n", TNS_ACCEPT_LEN_MIN);
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    }

    tnsdata_len = *(tnsbodyptr + 10);
    tnsdata_len <<= 8;
    tnsdata_len += *(tnsbodyptr + 11);

    tnsdata_offset = *(tnsbodyptr + 12);
    tnsdata_offset <<= 8;
    tnsdata_offset += *(tnsbodyptr + 13);
    DEBUG_LOG(DBG_PARSER, p, "tns: accept: data len(%u) offset(%u)\n", tnsdata_len, tnsdata_offset);

    if (tnsdata_offset + tnsdata_len > len) {
        DEBUG_LOG(DBG_PARSER, p, "tns: accept: abnormal accept data len(%hu).\n", tnsdata_len);
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    }

    *rc = TNS_PASS;
    return len;
}

static uint16_t tns_redir_connect_addr(dpi_packet_t *p, uint8_t *tnsbodyptr, uint16_t tnsdata_len, uint16_t pos, int *rc)
{
    uint16_t start;
    uint16_t count = 0;
    uint32_t port=0;
    char redirect_prtl[TNS_FLD_LEN];
    char host[TNS_FLD_LEN];

    while (pos < tnsdata_len && *(tnsbodyptr + pos) != ')') {
        switch (*(tnsbodyptr + pos)) {
            case 'P':
            case 'p':
                if (tnsdata_len - pos > 8 && strncasecmp((char *)(tnsbodyptr + pos + 1), "ROTOCOL", 7) == 0) {
                    pos += 8;

                    CONTINUE_ON_GROUP()
                    start = pos;
                    SKIP_GROUP()

                    strlcpy(redirect_prtl, (char *)(tnsbodyptr + start), pos - start + 1);

                    DEBUG_LOG(DBG_PARSER, p, "tns: redirect: connect protocol (%s)\n",redirect_prtl);

                    if (pos - start > 2 && strncasecmp((char *)(tnsbodyptr + start), "TCP", 3) == 0) {
                        count++;
                    }
                } else if (tnsdata_len - pos > 4 && strncasecmp((char *)(tnsbodyptr + pos + 1), "ORT", 3) == 0) {
                    pos += 4;
                    CONTINUE_ON_GROUP()
                    start = pos;

                    SKIP_GROUP()

                    if ( pos - start > 0 && pos - start < 6) {
                        port = strtoul((char *)(tnsbodyptr + start), 0, 10);
                        if (port > TNS_PORT_MAX) {
                            DEBUG_LOG(DBG_PARSER, p, "tns: redirect: connect port (%u) > (%d)\n", port, TNS_PORT_MAX);
                        } else {
                           count++;
                        }
                    } else {
                        if (pos - start > 0) {
                            char tmport[pos - start + 1];
                            strlcpy(tmport, (char *)(tnsbodyptr + start), pos - start + 1);
                            DEBUG_LOG(DBG_PARSER, p, "tns: redirect: connect port (%s) abnormal \n", tmport);
                        }
                    }
                    DEBUG_LOG(DBG_PARSER, p, "tns: redirect: port (%u)\n", port);
                } else {
                    SKIP_GROUP()
                }
                break;
            case 'H':
            case 'h':
                if (tnsdata_len - pos > 4 && strncasecmp((char *)(tnsbodyptr + pos + 1), "OST", 3) == 0) {
                    pos += 4;
                    CONTINUE_ON_GROUP()
                    start = pos;

                    SKIP_GROUP()

                    strlcpy(host, (char *)(tnsbodyptr + start), pos - start + 1);

                    DEBUG_LOG(DBG_PARSER, p, "tns: redirect: host (%s)\n", host);
                    if ( pos - start > 6) {
                        count++;
                    }
                } else {
                    SKIP_GROUP()
                }
                break;
            default:
                if (isalpha(*(tnsbodyptr + pos))) {
                    SKIP_GROUP()
                }
        }
        pos++;
    }
    if (count == 3) {
        *rc = TNS_PASS;
    }
    return pos;
}

static uint32_t tns_redirect(dpi_packet_t *p, uint8_t *ptr, uint32_t len, int *rc) {
    uint8_t *tnsbodyptr = ptr + TNS_HDR_LEN;
    uint32_t tnsbody_len = len - TNS_HDR_LEN;
    uint16_t tnsdata_offset, tnsdata_len;
    uint16_t pos = 0;

    if (dpi_is_client_pkt(p)) {
        DEBUG_LOG(DBG_PARSER, p, "tns: redirect: packet not from server side\n");
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    }

    if (tnsbody_len < TNS_REDIR_LEN_MIN) {
        DEBUG_LOG(DBG_PARSER, p, "tns: redirect body length < (%d)\n",TNS_REDIR_LEN_MIN);
        dpi_fire_parser(p);
        *rc = TNS_NOTPASS;
        return len;
    } else {
        tnsdata_len = *(tnsbodyptr);
        tnsdata_len <<= 8;
        tnsdata_len += *(tnsbodyptr + 1);

        tnsdata_offset = 2;

        DEBUG_LOG(DBG_PARSER, p, "tns: redirect: data len(%u) offset(%u)\n", tnsdata_len, tnsdata_offset);

        if (tnsdata_offset + tnsdata_len > tnsbody_len) {
            DEBUG_LOG(DBG_PARSER, p, "tns: redirect: abnormal data length\n");
            dpi_fire_parser(p);
            *rc = TNS_NOTPASS;
            return len;
        } else {
            if ( tnsdata_len == 0) {
                return len;
            }

            tnsbodyptr += tnsdata_offset;

            while (pos < tnsdata_len && *(tnsbodyptr + pos) != ')') {
                switch (*(tnsbodyptr + pos)) {
                    case 'A':
                    case 'a':
                        if (tnsdata_len - pos > 7 && strncasecmp((char *)(tnsbodyptr + pos + 1),
                            "DDRESS", 6) == 0) {
                            pos += 7;
                            pos = tns_redir_connect_addr(p, tnsbodyptr, tnsdata_len, pos, rc);

                            END_OF_PARAM()
                        }
                        break;
                   default:
                        if (isalpha(*(tnsbodyptr + pos))) {
                            END_OF_PARAM()
                        }
                }
                pos++;
            }
        }
    }
    return pos + tnsdata_offset + TNS_HDR_LEN;
}

static uint32_t tns_data(dpi_packet_t *p, uint8_t* ptr, uint32_t len, int *rc) {

    uint8_t *tnsbodyptr = ptr + TNS_HDR_LEN;
    uint32_t tnsbody_len = len - TNS_HDR_LEN;
    uint16_t tnsdata_offset, tnsdata_len;
    uint8_t data_id = 0;
    uint8_t data_callid = 0;
    uint16_t pos = 0;
    uint16_t start = 0;

    if (tnsbody_len < TNS_DATA_LEN_MIN) {
        DEBUG_LOG(DBG_PARSER, p, "tns: data: minimum length is (%d)\n",TNS_DATA_LEN_MIN);
        *rc = TNS_NOTPASS;
        return len;
    }

    if (tnsbody_len > 4) {
        tnsdata_len = tnsbody_len - 4;
        tnsdata_offset = 4;

        data_id = *(tnsbodyptr + 2);
        data_callid = *(tnsbodyptr + 3);

        tnsbodyptr += tnsdata_offset;
        if ((data_id == TNS_DATAID_SQL_USER_OCI && data_callid == TNS_DATA_CALLID_BEC) || 
            (data_id == TNS_DATAID_SQL_PIGGYBACK && 
            (data_callid == TNS_DATA_CALLID_CCC || data_callid == TNS_DATA_CALLID_SSP))) {  
            while (pos < tnsdata_len) {
                switch (*(tnsbodyptr + pos)) {
                    case 'S':
                    case 's':
                        if (tnsdata_len - pos > 6 && strncasecmp((char *)(tnsbodyptr + pos + 1),
                            "ELECT", 5) == 0) {
                            start = pos;
                            SKIP_TO_END_OF_SELECT()
                            p->dlp_area[DPI_SIG_CONTEXT_TYPE_SQL_QUERY].dlp_start = dpi_pkt_seq(p) + (tnsbodyptr + start - ptr);
                            p->dlp_area[DPI_SIG_CONTEXT_TYPE_SQL_QUERY].dlp_end = p->dlp_area[DPI_SIG_CONTEXT_TYPE_SQL_QUERY].dlp_start + (pos - start);
                            //embedded sql injection threat detection
                            check_sql_query(p, tnsbodyptr + start, pos - start, DPI_APP_TNS);
                        }
                        break;
                    default:
                        break;
                }
                pos++;
            }
            *rc = TNS_PASS;
            return pos + tnsdata_offset + TNS_HDR_LEN;
        }
        if ((data_id == TNS_DATAID_SQL_USER_OCI && data_callid == TNS_DATA_CALLID_GAC) ||
            data_id == TNS_DATAID_SQL_USER_ROP) {//this is to ignore this pkt for dlp detection
            dpi_dlp_area_t *dlparea = &p->dlp_area[DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN];
            uint32_t pkt_seq = dpi_pkt_seq(p);
            uint32_t pkt_end_seq = dpi_pkt_end_seq(p);
            dlparea->dlp_start = pkt_end_seq;
            dlparea->dlp_ptr = dpi_pkt_ptr(p) + dlparea->dlp_start - pkt_seq;
            dlparea->dlp_offset = 0;
            dlparea->dlp_end = pkt_end_seq;
            dlparea->dlp_len = dlparea->dlp_end - dlparea->dlp_start - dlparea->dlp_offset;
        }
    }
    *rc = TNS_PASS;
    return len;
}

static void tns_parser(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    tns_data_t *data;
    tns_wing_t *w;
    uint8_t *ptr;
    uint32_t len;
    tns_header_t* tnshdr = NULL;
    int rc = TNS_NOTPASS;
    uint32_t rlen = 0;
    uint32_t tnspktlen = 0;
    uint16_t tnschksm = 0;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not tns: First packet from server\n");
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

    if (len < TNS_HDR_LEN) {
        /*not enough length to hold tns header*/
        dpi_fire_parser(p);
        return;
    }

    while (len >= TNS_HDR_LEN) {

        tnshdr = (tns_header_t*)ptr;
        /*
         * In some messages (observed in Oracle12c) packet length has 4 bytes
         * instead of 2.
         * If packet length has 2 bytes, length and checksum equals two unsigned
         * 16-bit numbers. Packet checksum is generally unused (equal zero),
         * but 10g client may set 2nd byte to 4.
         * Else, Oracle 12c combine these two 16-bit numbers into one 32-bit.
         * This number represents the packet length. Checksum is omitted.
         */
        tnschksm = ntohs(tnshdr->pktchksm);
        if (tnschksm == 0 || tnschksm == 4) {
            tnspktlen = ntohs(tnshdr->pktlen);
        } else {
            tnspktlen = ntohs(tnshdr->pktlen);
            tnspktlen <<= 16;
            tnspktlen += ntohs(tnshdr->pktchksm);
        }

        if (tnspktlen < TNS_HDR_LEN) {
            /*wrong tns packet length value*/
            dpi_fire_parser(p);
            return;
        }

        /*
         * In the case of tcp segamentation offload,  
         * tns content may be accross serveral 
         * packet, we do not move p->parser_asm_seq
         * until all the PDUs got assembled.
         */
        DEBUG_LOG(DBG_PARSER, p, "tns pkt length (%hu), len(%u)\n", tnspktlen, len);
        if (tnspktlen > len) {
            if (tnspktlen > TNS_PKT_LEN_MAX) {
                /* abnormal tns pktlen */
                dpi_fire_parser(p);
                return;
            }
            return;
        }

        switch (tnshdr->pkttype) {
            case TNS_TYPE_CONNECT:
                rlen = tns_connect(p, ptr, len, &rc);
                DEBUG_LOG(DBG_PARSER, p, "tns: connect: parser position(%u) pktlen(%u), rc(%d)\n", rlen, len, rc);
                break;

            case TNS_TYPE_ACCEPT:
                rlen = tns_accept( p, ptr, len, &rc);
                DEBUG_LOG(DBG_PARSER, p, "tns: accept: parser position(%u) pktlen(%u), rc(%d)\n", rlen, len, rc);
                break;

            case TNS_TYPE_REDIRECT:
                rlen = tns_redirect( p, ptr, len, &rc);
                DEBUG_LOG(DBG_PARSER, p, "tns: redirect: parser position(%u) pktlen(%u), rc(%d)\n", rlen, len, rc);
                break;

            case TNS_TYPE_DATA:
                rlen = tns_data( p, ptr, len, &rc);
                DEBUG_LOG(DBG_PARSER, p, "tns: data: parser position(%u) pktlen(%u), rc(%d)\n", rlen, len, rc);
                break;
            case TNS_TYPE_REFUSE:
            case TNS_TYPE_ACK:
            case TNS_TYPE_NULL:
            case TNS_TYPE_ABORT:
            case TNS_TYPE_RESEND:
            case TNS_TYPE_MARKER:
            case TNS_TYPE_ATTENTION:
            case TNS_TYPE_CONTROL:
            if (dpi_is_parser_final(p)) {
                rc = TNS_PASS;
                DEBUG_LOG(DBG_PARSER, p, "tns: type(%d)\n", tnshdr->pkttype);
                break;
            } else {
                DEBUG_LOG(DBG_PARSER, p, "tns: not type(%d)\n", tnshdr->pkttype);
                dpi_fire_parser(p);
                return;
            }

            default:
                DEBUG_LOG(DBG_PARSER, p, "not tns: unknown type(%d)\n", tnshdr->pkttype);
                dpi_fire_parser(p);
                return;
        }

        ptr += tnspktlen;
        len -= tnspktlen;
        w->seq = dpi_ptr_2_seq(p, ptr);
        dpi_set_asm_seq(p, w->seq);
    }

    if (len > 0) {
        dpi_fire_parser(p);
    }
    
    if (!dpi_is_parser_final(p) && rc == TNS_PASS) {
        dpi_finalize_parser(p);
    }
}

static void tns_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void tns_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_tns = {
    new_session: tns_new_session,
    delete_data: tns_delete_data,
    parser:      tns_parser,
    name:        "tns",
    ip_proto:    IPPROTO_TCP,
    type:        DPI_PARSER_TNS,
};

dpi_parser_t *dpi_tns_tcp_parser(void)
{
    return &dpi_parser_tns;
}
