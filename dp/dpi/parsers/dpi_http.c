#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#define HTTP_HEADER_COMPLETE_TIMEOUT 3
#define HTTP_BODY_FIRST_TIMEOUT      30
#define HTTP_BODY_INTERVAL_TIMEOUT   3

typedef struct http_wing_ {
    uint32_t seq;
    uint32_t content_len;
#define HTTP_FLAGS_CONTENT_LEN  0x01
#define HTTP_FLAGS_CHUNKED      0x02
#define HTTP_FLAGS_CONN_CLOSE   0x04
#define HTTP_FLAGS_REQUEST      0x08
#define HTTP_FLAGS_NEGATIVE_LEN 0x10
    uint8_t flags;
#define HTTP_SECTION_NONE       0
#define HTTP_SECTION_REQ_RESP   1
#define HTTP_SECTION_HEADER     2
#define HTTP_SECTION_FIRST_BODY 3
#define HTTP_SECTION_BODY       4
    uint8_t section:3,
#define HTTP_CHUNK_LENGTH     0
#define HTTP_CHUNK_CONTENT    1
#define HTTP_CHUNK_LAST       2
            chunk:  2;
#define HTTP_CTYPE_NONE                0
#define HTTP_CTYPE_APPLICATION_XML     1
    uint8_t ctype:  3,
#define HTTP_ENCODE_NONE      0
#define HTTP_ENCODE_GZIP      1
#define HTTP_ENCODE_COMPRESS  2
#define HTTP_ENCODE_DEFLATE   3
            encode: 2;
    uint32_t cmd_start;
    uint32_t body_start;
    uint32_t hdr_start;
} http_wing_t;

typedef struct http_data_ {
    http_wing_t client, server;
    uint16_t status:10,
#define HTTP_METHOD_NONE   0
#define HTTP_METHOD_GET    1
#define HTTP_METHOD_POST   2
#define HTTP_METHOD_PUT    3
#define HTTP_METHOD_DELETE 4
#define HTTP_METHOD_HEAD   5
             method:4,
#define HTTP_PROTO_NONE 0
#define HTTP_PROTO_HTTP 1
#define HTTP_PROTO_SIP  2
#define HTTP_PROTO_RTSP 3
             proto :2;
    uint16_t body_buffer_len; // TODO: temp. way to buffer body in some cases.
    uint32_t url_start_tick;
    uint32_t last_body_tick;
    uint8_t *body_buffer; // TODO: temp. way to buffer body in some cases.
} http_data_t;

typedef struct http_ctx_ {
    dpi_packet_t *p;
    http_data_t *data;
    http_wing_t *w;
} http_ctx_t;

typedef struct http_method_ {
    char *name;
    uint8_t len;
    uint8_t proto;
    uint8_t method;
} http_method_t;

static http_method_t http_method[] = {
    {"GET",     3, HTTP_PROTO_HTTP, HTTP_METHOD_GET},
    {"PUT",     3, HTTP_PROTO_HTTP, HTTP_METHOD_PUT},
    {"POST",    4, HTTP_PROTO_HTTP, HTTP_METHOD_POST},
    {"DELETE",  6, HTTP_PROTO_HTTP, HTTP_METHOD_DELETE},
    {"HEAD",    4, HTTP_PROTO_HTTP, HTTP_METHOD_HEAD},
    {"CONNECT", 7, HTTP_PROTO_HTTP, HTTP_METHOD_NONE},
};

/*
typedef struct couchbase_handle_ {
    char *name;
    uint8_t len;
} couchbase_handle_t;

const static  couchbase_handle_t couchbase_headers[] = {
    {"/createIndex",            sizeof("/createIndex")},
    {"/dropIndex",              sizeof("/dropIndex")},
    {"/getLocalIndexMetadata",  sizeof("/getLocalIndexMetadata")},
    {"/getIndexMetadata",       sizeof("/getIndexMetadata")},
    {"/restoreIndexMetadata",   sizeof("/restoreIndexMetadata")},
    {"/getIndexStatus",         sizeof("/getIndexStatus")},
    {"/api/indexes",            sizeof("/api/indexes")},
    {"/api/index/",             sizeof("/api/index/")},
    //{"/settings",               sizeof("/settings")},
    {"/triggerCompaction",      sizeof("/triggerCompaction")}
    //{"/stats",                  sizeof("/stats")},
    //{"/pools",                  sizeof("/pools")}
};

static bool is_couchbase_request(uint8_t * ptr, int len)
{
    int i;

    for (i=0; i < sizeof(couchbase_headers)/sizeof(couchbase_headers[0]); i++) {
        if ((couchbase_headers[i].len-1) > len) {
            continue;
        }
        if ( memcmp(ptr, couchbase_headers[i].name, couchbase_headers[i].len-1) == 0) {
            DEBUG_LOG(DBG_PARSER, NULL, "Couchbase request: %s\n", couchbase_headers[i].name);
            return true;
        }
    }
    return false;
}
*/

int dpi_http_tick_timeout(dpi_session_t *s, void *parser_data)
{
    http_data_t *data = parser_data;

    DEBUG_LOG_FUNC_ENTRY(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL);

    if (data->url_start_tick > 0) {
        if (th_snap.tick - data->url_start_tick >= HTTP_HEADER_COMPLETE_TIMEOUT) {
            DEBUG_LOG(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL,
                      "Header duration=%us, threshold=%us\n",
                      th_snap.tick - data->url_start_tick, HTTP_HEADER_COMPLETE_TIMEOUT);
            dpi_threat_log_by_session(DPI_THRT_HTTP_SLOWLORIS, s,
                      "Header duration=%us, threshold=%us",
                      th_snap.tick - data->url_start_tick, HTTP_HEADER_COMPLETE_TIMEOUT);
            return DPI_SESS_TICK_RESET;
        }
    } else if (data->last_body_tick > 0) {
        switch (data->client.section) {
        case HTTP_SECTION_FIRST_BODY:
            if (th_snap.tick - data->last_body_tick >= HTTP_BODY_FIRST_TIMEOUT) {
                DEBUG_LOG(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL,
                          "First body packet interval=%us, threshold=%us\n",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                dpi_threat_log_by_session(DPI_THRT_HTTP_SLOWLORIS, s,
                          "First body packet interval=%us, threshold=%us",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                return DPI_SESS_TICK_RESET;
            }
            break;
        case HTTP_SECTION_BODY:
            /* Easy to get false positive, maybe 3s is too short.
            if (th_snap.tick - data->last_body_tick >= HTTP_BODY_INTERVAL_TIMEOUT) {
                DEBUG_LOG(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL,
                          "Body packet interval=%us, threshold=%us\n",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                dpi_threat_log_by_session(DPI_THRT_HTTP_SLOWLORIS, s,
                          "Body packet interval=%us, threshold=%us",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                return DPI_SESS_TICK_RESET;
            }
            */
            break;
        }
    }

    return DPI_SESS_TICK_CONTINUE;
}

static inline bool to_detect_slowloris_body_attack(http_data_t *data, http_wing_t *w)
{
    return data->method != HTTP_METHOD_GET && data->method != HTTP_METHOD_HEAD &&
           (w->flags & HTTP_FLAGS_CONTENT_LEN) && w->content_len > 0;
}

static inline bool is_request_delimiter(char c)
{
    return (c == ' ' || c == '\t');
}

static inline bool is_request(http_wing_t *w)
{
    return FLAGS_TEST(w->flags, HTTP_FLAGS_REQUEST);
}

static int http_parse_response(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    int status = 0;
    char *cptr = (char *)ptr;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    if (unlikely(len < 4)) return 0;
    if (likely(strncmp(cptr, "HTTP", 4) == 0 || strncmp(cptr, "RTSP", 4) == 0 ||
               strncmp(cptr, "SIP", 3) == 0)) {
        uint8_t *l = ptr, *end = ptr + len;
        uint8_t *status_ptr = NULL;
        int version_end = 0;

        while (l < end) {
            if (!isprint(*l)) {
                return -1;
            }

            if (isblank(*l)) {
                if (status_ptr != NULL) {
                    // Valid status line
                    int eols;
                    uint8_t *eol = consume_line(l, end - l, &eols);
                    if (eol != NULL) {
                        ctx->data->status = status;
                        return eol - ptr;
                    } else {
                        // Wait for eol
                        return 0;
                    }
                } else {
                    version_end = l - ptr;
                }
            } else if (version_end > 0) {
                // Parse status code
                if (!isdigit(*l)) {
                    return -1;
                }

                if (status_ptr == NULL) {
                    status_ptr = l;
                } else if (l - status_ptr >= 3) {
                    return -1;
                }

                status = status * 10 + ctoi(*l);
            }

            l ++;
        }

        // EOL is not reached, wait.
        return 0;
    }

    return -1;
}

static int http_parse_request(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    int i;
    uint8_t *l = ptr, *end = ptr + len, *eol = NULL;
    uint8_t proto = HTTP_PROTO_NONE;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    for (i = 0; i < sizeof(http_method) / sizeof(http_method[0]); i ++) {
        http_method_t *m = &http_method[i];
        if (len > m->len + 1 && is_request_delimiter(ptr[m->len]) &&
            strncasecmp((char *)ptr, m->name, m->len) == 0) {
            proto = m->proto;
            ctx->data->method = m->method;
            break;
        }
    }

    struct {
        uint8_t *start, *end;
    } part[3];
    int n = 0;

    part[0].start = ptr; part[1].start = part[2].start = NULL;
    part[0].end = part[1].end = part[2].end = NULL;

    while (l < end) {
        if (is_request_delimiter(*l)) {
            if (n >= 2) return -1;      // At most 3 parts
            if (l - ptr < 3) return -1; // Shortest method is 3-char
            while (l+1 < end && is_request_delimiter(*(l+1))) l ++; //skip consecutive delimiter

            if (part[n].end == NULL) {
                part[n].end = l;
                n ++;
            }
        } else if (*l == '\n') {
            if (part[n].end == NULL) {
                part[n].end = *(l - 1) == '\r' ? l - 1 : l;
            }

            eol = l + 1;
            break;
        } else {
            if (part[n].start == NULL) {
                part[n].start = l;
            }
            if (n == 2 && l - part[n].start > 8) return -1;
            if (n == 0 && l - part[n].start > 16) return -1;
        }

        l ++;
    }

    if (eol == NULL) return 0;
    if (n == 0) return -1;
    if (part[n].start == NULL || part[n].start == part[n].end) n --; // "GET \r\n", "GET /abc \r\n"
    if (n == 0) return -1;
    if (n == 1 && proto == HTTP_PROTO_NONE) return -1;
    if (n == 2) {
        if (part[2].end - part[2].start <= 5) return -1;

        if (strncmp((char *)part[2].start, "HTTP/", 5) == 0) {
            proto = HTTP_PROTO_HTTP;
        } else if (strncmp((char *)part[2].start, "RTSP/", 5) == 0) {
            proto = HTTP_PROTO_RTSP;
        } else if (strncmp((char *)part[2].start, "SIP/", 4) == 0) {
            proto = HTTP_PROTO_SIP;
        } else if (proto == HTTP_PROTO_NONE) {
            return -1;
        }
    }

    ctx->data->proto = proto;

    // TODO: move to signature
    if (part[1].end - part[1].start > 12 && memcmp(part[1].start, "/wp-content/", 12) == 0) {
        dpi_ep_set_app(ctx->p, 0, DPI_APP_WORDPRESS);
    }

    // check couchbase
    /* If server side ep is already marked as couchbase, ep's applicaiton should be already assigned.
    if ((ctx->p->ep->couchbase_svr && (ctx->p->session->flags & DPI_SESS_FLAG_INGRESS)) &&
        is_couchbase_request(part[1].start, part[1].end - part[1].start)) {
        dpi_ep_set_app(ctx->p, 0, DPI_APP_COUCHBASE);
    }
    */

    return eol - ptr;
}
static void set_body_done(http_wing_t *w)
{
    w->flags &= ~(HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CONN_CLOSE | HTTP_FLAGS_CHUNKED |
                  HTTP_FLAGS_NEGATIVE_LEN);
    w->content_len = 0;
}

static void set_body_conn_close(http_wing_t *w)
{
    w->flags |= HTTP_FLAGS_CONN_CLOSE;
    w->flags &= ~(HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CHUNKED);
    w->content_len = 0;
}

static void set_body_chunked(http_wing_t *w)
{
    w->flags |= HTTP_FLAGS_CHUNKED;
    w->flags &= ~(HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CONN_CLOSE);
    w->content_len = 0;
}

static void set_body_content_length(http_wing_t *w)
{
    w->flags |= HTTP_FLAGS_CONTENT_LEN;
    w->flags &= ~(HTTP_FLAGS_CONN_CLOSE | HTTP_FLAGS_CHUNKED);
}

static int http_header_content_length_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    register uint8_t *l = ptr, *end = ptr + len;
    int clen = 0;

    if (unlikely(*l == '-')) {
        ctx->w->flags |= HTTP_FLAGS_NEGATIVE_LEN;
        return CONSUME_TOKEN_SKIP_LINE;
    } else if (unlikely(*l == '+')) {
        l ++;
    }

    while (l < end) {
        if (likely(isdigit(*l))) {
            clen = clen * 10 + ctoi(*l);
        }

        l ++;
    }

    ctx->w->content_len = clen;
    return CONSUME_TOKEN_SKIP_LINE;
}

static void http_header_content_length(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    dpi_packet_t *p = ctx->p;
    http_wing_t *w = ctx->w;
    int content_len = w->content_len;

    consume_tokens(ptr, len, http_header_content_length_token, ctx);
    if (w->flags & HTTP_FLAGS_NEGATIVE_LEN) {
        dpi_threat_trigger(DPI_THRT_HTTP_NEG_LEN, p, "Content-Length header has negative value");
        set_body_conn_close(w);
    /* Disable this logic because some apps may send both content-length and chunked-encoding together
    } else if ((w->flags & HTTP_FLAGS_CHUNKED)) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, p, "Both Content-Length and chunked headers present");
        set_body_conn_close(w);
    */
    } else if ((w->flags & HTTP_FLAGS_CONTENT_LEN) && content_len != w->content_len) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, p, "Two Content-Length headers with different values");
        set_body_conn_close(w);
    /* Disable this logic because GET with data is pretty common today.
    } else if (ctx->data->method == HTTP_METHOD_GET && is_request(w) && dpi_is_client_pkt(p) && w->content_len > 0) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, p, "GET request's Content-Length header has non-zero value");
        set_body_conn_close(w);
    */
    } else {
        DEBUG_LOG(DBG_PARSER, p, "len=%u\n", w->content_len);

        set_body_content_length(w);
    }
}

static int http_header_content_type_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    if (strncasecmp((char *)ptr, "application/xml", 15) == 0) {
        http_ctx_t *ctx = param;
        http_wing_t *w = ctx->w;

        w->ctype = HTTP_CTYPE_APPLICATION_XML;
        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

static void http_header_content_type(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_content_type_token, ctx);
}

static int http_header_content_encoding_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    http_wing_t *w = ctx->w;

    if (strncmp((char *)ptr, "gzip", 4) == 0 || strncmp((char *)ptr, "x-gzip", 6) == 0) {
        w->ctype = HTTP_ENCODE_GZIP;
        return CONSUME_TOKEN_SKIP_LINE;
    } else if (strncmp((char *)ptr, "compress", 8) == 0) {
        w->ctype = HTTP_ENCODE_COMPRESS;
        return CONSUME_TOKEN_SKIP_LINE;
    } else if (strncmp((char *)ptr, "deflate", 7) == 0) {
        w->ctype = HTTP_ENCODE_DEFLATE;
        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

static void http_header_content_encoding(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_content_encoding_token, ctx);
}

static int http_header_connection_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    if (strncasecmp((char *)ptr, "close", 5) == 0) {
        http_ctx_t *ctx = param;
        http_wing_t *w = ctx->w;

        if ((w->flags & HTTP_FLAGS_CHUNKED) ||
            ((w->flags & HTTP_FLAGS_CONTENT_LEN) && w->content_len > 0)) {
            // Ignore connection close flag
        } else {
            DEBUG_LOG(DBG_PARSER, ctx->p, "close\n");
            set_body_conn_close(w);
        }

        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

static void http_header_connection(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_connection_token, ctx);
}

static int http_header_xfr_encoding_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;

    if (len == 7 && strncasecmp((char *)ptr, "chunked", 7) == 0) {
        DEBUG_LOG(DBG_PARSER, ctx->p, "chunked\n");

        ctx->w->flags |= HTTP_FLAGS_CHUNKED;
        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

static void http_header_xfr_encoding(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    http_wing_t *w = ctx->w;

    consume_tokens(ptr, len, http_header_xfr_encoding_token, ctx);
    if ((w->flags & HTTP_FLAGS_CHUNKED)) {
        set_body_chunked(w);
    }
    /* Disable this logic because some apps may send both content-length and chunked-encoding together
    if ((w->flags & HTTP_FLAGS_CHUNKED) &&
        (w->flags & HTTP_FLAGS_CONTENT_LEN) && w->content_len > 0) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, ctx->p, "Both Content-Length and chunked headers present");
        set_body_conn_close(w);
    } else {
        set_body_chunked(w);
    }
    */
}

static int http_header_xforwarded_port_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;
    register uint8_t *l = ptr, *end = ptr + len;
    uint16_t xffport = 0;

    while (l < end) {
        if (likely(isdigit(*l))) {
            xffport = xffport * 10 + ctoi(*l);
        } else if (unlikely(*l == ',')) {
            break;
        }
        l ++;
    }

    s->xff_port = xffport;

    DEBUG_LOG(DBG_PARSER, p, "X-Forwarded-Port: %d\n",s->xff_port);

    return CONSUME_TOKEN_SKIP_LINE;
}

static void http_header_xforwarded_port(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_xforwarded_port_token, ctx);
}

static int http_header_xforwarded_proto_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;

    if (strncmp((char *)ptr, "https", 5) == 0) {
        s->xff_app = DPI_APP_SSL;
    } else if (strncmp((char *)ptr, "http", 4) == 0) {
        s->xff_app = DPI_APP_HTTP;
    }

    DEBUG_LOG(DBG_PARSER, p, "X-Forwarded-Proto: %d\n",s->xff_app);

    return CONSUME_TOKEN_SKIP_LINE;
}

static void http_header_xforwarded_proto(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_xforwarded_proto_token, ctx);
}

static int http_header_xforwarded_for_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;
    char *ip_str;
    int ip_str_len;
    register uint8_t *l = ptr, *end = ptr + len;

    while (l < end) {
        if (unlikely(*l == ',')) {
            break;
        }
        l ++;
    }
    ip_str_len = l-ptr;

    //preallocated memory
    ip_str = (char *) calloc(ip_str_len + 1, sizeof(char));
    if (ip_str == NULL) {
        return CONSUME_TOKEN_SKIP_LINE;
    }
    strncpy(ip_str, (char *)ptr, ip_str_len);
    //ip_str is null terminated
    ip_str[ip_str_len] = '\0';
    s->xff_client_ip = inet_addr(ip_str);
    if (s->xff_client_ip == (uint32_t)(-1)) {
        DEBUG_LOG(DBG_PARSER, p, "ipv6 or wrong format ipv4: %s, ip=0x%08x\n",ip_str, s->xff_client_ip);
        s->xff_client_ip = 0;
        return CONSUME_TOKEN_SKIP_LINE;
    }
    s->flags |= DPI_SESS_FLAG_XFF;

    DEBUG_LOG(DBG_PARSER, p, "X-Forwarded-For: %s, ip=0x%08x, sess flags=0x%04x\n",ip_str, s->xff_client_ip, s->flags);

    //memory freed
    free(ip_str);
    return CONSUME_TOKEN_SKIP_LINE;
}

static void http_header_xforwarded_for(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_xforwarded_for_token, ctx);
}

static int http_header_host_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;
    uint16_t host_str_len;
    register uint8_t *l = ptr, *end = ptr + len;

    while (l < end) {
        if (unlikely(*l == ':')) {
            break;
        }
        l ++;
    }
    host_str_len = l-ptr;
    int size = min(host_str_len+1, sizeof(s->vhost));
    strlcpy((char *)s->vhost, (char *)ptr, size);

    s->vhlen = size-1;
    DEBUG_LOG(DBG_PARSER, p, "vhostname(%s) vhlen(%hu)\n", (char *)s->vhost, s->vhlen);

    return CONSUME_TOKEN_SKIP_LINE;
}

static void http_header_host(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_host_token, ctx);
}

static int http_header_server_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;

    if (len >= 6 && strncasecmp((char *)ptr, "apache", 6) == 0) {
        dpi_ep_set_app(p, DPI_APP_APACHE, 0);
    } else if (len >= 5 && strncasecmp((char *)ptr, "nginx", 5) == 0) {
        dpi_ep_set_app(p, DPI_APP_NGINX, 0);
    } else if (len >= 5 && strncasecmp((char *)ptr, "jetty", 5) == 0) {
        dpi_ep_set_app(p, DPI_APP_JETTY, 0);
    } else if (len >= 9 && strncasecmp((char *)ptr, "couchbase", 9) == 0) {
        dpi_ep_set_app(p, 0, DPI_APP_COUCHBASE);
        DEBUG_LOG(DBG_PARSER, p, "http: couchbase server\n");
    } else if (len >= 7 && strncasecmp((char *)ptr, "couchdb", 7) == 0) {
        dpi_ep_set_app(p, 0, DPI_APP_COUCHDB);
        DEBUG_LOG(DBG_PARSER, p, "http: couchdb server\n");
    }

    dpi_ep_set_server_ver(p, (char *)ptr, len);

    return CONSUME_TOKEN_SKIP_LINE;
}

static void http_header_server(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_server_token, ctx);
}

static int http_parse_header(http_ctx_t *ctx, uint8_t *ptr, int len, bool *done)
{
    dpi_packet_t *p = ctx->p;
    uint8_t *end = ptr + len;
    int consume = 0;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, p);

    *done = false;
    while (true) {
        int eols, shift;
        uint8_t *eol = consume_line(ptr, end - ptr, &eols);

        if (eol == NULL) return consume;

        shift = eol - ptr;
        if (shift == eols) {
            // Empty line, end of header
            DEBUG_LOG(DBG_PARSER, ctx->p, "done\n");
            *done = true;
            return consume + shift;
        }

        // TODO: replace this to keyword parser
        if (shift > 15 && strncasecmp((char *)ptr, "Content-Length:", 15) == 0) {
            http_header_content_length(ctx, ptr + 15, shift - eols - 15);
        } else
        if (shift > 13 && strncasecmp((char *)ptr, "Content-Type:", 13) == 0) {
            http_header_content_type(ctx, ptr + 13, shift - eols - 13);
        } else
        if (shift > 17 && strncasecmp((char *)ptr, "Content-Encoding:", 17) == 0) {
            http_header_content_encoding(ctx, ptr + 17, shift - eols - 17);
        } else
        if (shift > 11 && strncasecmp((char *)ptr, "Connection:", 11) == 0) {
            http_header_connection(ctx, ptr + 11, shift - eols - 11);
        } else
        if (shift > 5 && strncasecmp((char *)ptr, "Host:", 5) == 0) {
            http_header_host(ctx, ptr + 5, shift - eols - 5);
        } else
        if (shift > 18 && strncasecmp((char *)ptr, "Transfer-Encoding:", 18) == 0) {
            http_header_xfr_encoding(ctx, ptr + 18, shift - eols - 18);
        } else
        if (shift > 18 && strncasecmp((char *)ptr, "X-Etcd-Cluster-Id:", 18) == 0) {
            dpi_ep_set_app(ctx->p, 0, DPI_APP_ETCD);
        } else
        if (shift > 17 && strncasecmp((char *)ptr, "X-Forwarded-Port:", 17) == 0) {
            http_header_xforwarded_port(ctx, ptr + 17, shift - eols - 17);
        } else
        if (shift > 18 && strncasecmp((char *)ptr, "X-Forwarded-Proto:", 18) == 0) {
            http_header_xforwarded_proto(ctx, ptr + 18, shift - eols - 18);
        } else
        if (shift > 16 && strncasecmp((char *)ptr, "X-Forwarded-For:", 16) == 0) {
            http_header_xforwarded_for(ctx, ptr + 16, shift - eols - 16);
        } else if (!is_request(ctx->w)) {
            // TODO: move to signature
            if (shift > 7 && strncasecmp((char *)ptr, "Server:", 7) == 0) {
                http_header_server(ctx, ptr + 7, shift - eols - 7);
            }
        }

        len -= shift;
        ptr = eol;
        consume += shift;
    }

    return consume;
}

static int http_body_chunk(http_ctx_t *ctx, uint8_t *ptr, int len, bool *done)
{
    dpi_packet_t *p = ctx->p;
    http_wing_t *w = ctx->w;
    uint8_t *end = ptr + len, *eol;
    int consume = 0, shift, eols;

    *done = false;
    while (ptr < end) {
        switch (w->chunk) {
        case HTTP_CHUNK_LENGTH:
            eol = consume_line(ptr, end - ptr, &eols);
            if (eol == NULL) return consume;
            shift = eol - ptr;

            w->content_len = 0;
            while (ptr < eol) {
                int8_t hex = c2hex(*ptr);
                if (hex == -1) break;
                w->content_len = (w->content_len << 4) + hex;
                ptr ++;
            }

            DEBUG_LOG(DBG_PARSER, p, "len=%u\n", w->content_len);

            ptr = eol;
            len -= shift;
            consume += shift;

            if (w->content_len == 0) {
                w->chunk = HTTP_CHUNK_LAST;
            } else {
                if (w->content_len & 0x80000000) {
                    dpi_threat_trigger(DPI_THRT_HTTP_NEG_LEN, p, "Content-length header has negative value");
                }

                w->chunk = HTTP_CHUNK_CONTENT;
            }

            break;
        case HTTP_CHUNK_CONTENT:
            if (w->content_len > 0) {
                if (len < w->content_len) {
                    DEBUG_LOG(DBG_PARSER, p, "consume=%u\n", len);
                    w->content_len -= len;
                    return consume + len;
                } else {
                    DEBUG_LOG(DBG_PARSER, p, "chunk done, consume=%u\n", w->content_len);

                    ptr += w->content_len;
                    len -= w->content_len;
                    consume += w->content_len;

                    w->content_len = 0;
                }
            } else {
                eol = consume_line(ptr, end - ptr, &eols);
                if (eol == NULL) return consume;
                shift = eol - ptr;

                ptr = eol;
                len -= shift;
                consume += shift;

                w->chunk = HTTP_CHUNK_LENGTH;
            }

            break;
        case HTTP_CHUNK_LAST:
            eol = consume_line(ptr, end - ptr, &eols);
            if (eol == NULL) return consume;
            shift = eol - ptr;

            DEBUG_LOG(DBG_PARSER, p, "chunk last\n");

            w->chunk = HTTP_CHUNK_LENGTH;
            *done = true;

            return consume + shift;
        }
    }

    return consume;
}

#define APACHE_STRUTS_PCRE "class=[\"']java\\.lang\\.ProcessBuilder[\"']>[\\s\\n\\r]*<command>[\\s\\n\\r]*<string>\\/bin\\/sh<\\/string>"
static pcre2_code *apache_struts_re;

// TODO: temp. way to buffer body in some cases.
static void buffer_body(http_ctx_t *ctx, uint8_t *ptr, int len) {
    http_wing_t *w = ctx->w;

    // This is to specifically detect threats in client-side XML, e.g. CVE-2017-9805
    if (unlikely(is_request(w) && w->ctype == HTTP_CTYPE_APPLICATION_XML && w->encode == HTTP_ENCODE_NONE)) {
        http_data_t *data = ctx->data;
        if (data->body_buffer == NULL) {
            data->body_buffer = malloc(2048);
        }
        if (data->body_buffer != NULL && data->body_buffer_len < 2048) {
            int copy = min(len, 2048 - data->body_buffer_len);
            memcpy(&data->body_buffer[data->body_buffer_len], ptr, copy);
            data->body_buffer_len += copy;

            if (unlikely(th_apache_struts_re_data == NULL)) {
                th_apache_struts_re_data  = pcre2_match_data_create_from_pattern(apache_struts_re, NULL);
            }

            if (likely(th_apache_struts_re_data != NULL)) {
                int rc = pcre2_match(apache_struts_re,
                        (PCRE2_SPTR)data->body_buffer, data->body_buffer_len,
                        0, 0, th_apache_struts_re_data, NULL);
                if (rc >= 0) {
                    dpi_threat_trigger(DPI_THRT_APACHE_STRUTS_RCE, ctx->p, NULL);
                }
            }
        }
    }
}

static int http_parse_body(http_ctx_t *ctx, uint8_t *ptr, int len, bool *done)
{
    dpi_packet_t *p = ctx->p;
    http_wing_t *w = ctx->w;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, p);

    *done = false;
    if (w->flags & HTTP_FLAGS_CONN_CLOSE) {
        DEBUG_LOG(DBG_PARSER, p, "consume all=%u\n", len);
        return len;
    } else if (w->flags & HTTP_FLAGS_CHUNKED) {
        return http_body_chunk(ctx, ptr, len, done);
    } else {
        if (len < w->content_len) {
            DEBUG_LOG(DBG_PARSER, p, "consume=%u\n", len);
            buffer_body(ctx, ptr, len);
            w->content_len -= len;
            return len;
        } else {
            DEBUG_LOG(DBG_PARSER, p, "body done. consume=%u\n", w->content_len);
            buffer_body(ctx, ptr, w->content_len);
            *done = true;
            return w->content_len;
        }
    }
}


static inline bool is_slowloris_on_for_wing(dpi_session_t *s, http_wing_t *w)
{
    return is_request(w) && dpi_session_check_tick(s, DPI_SESS_TICK_FLAG_SLOWLORIS);
}

static inline void overwrite_base_app(dpi_packet_t *p, uint16_t app)
{
    dpi_session_t *s = p->session;

    if (s->base_app != app) {
        s->base_app = app;
        dpi_ep_set_proto(p, app);
    }
}

static void http_parser(dpi_packet_t *p)
{
    http_ctx_t ctx;
    dpi_session_t *s = p->session;
    http_data_t *data;
    http_wing_t *w;
    uint8_t *ptr, *end;
    uint32_t len;

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not HTTP: First packet from server\n");
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

    ctx.p = p; ctx.data = data; ctx.w = w;

    end = ptr + len;
    while (ptr < end) {
        int shift;
        bool done;

        switch (w->section) {
        case HTTP_SECTION_NONE:
            if (isalpha(*ptr)) {
                w->section = HTTP_SECTION_REQ_RESP;
            } else if (dpi_is_client_pkt(p)) {
                dpi_fire_parser(p);
                return;
            } else {
                // Take all as body
                w->section = HTTP_SECTION_BODY;
                set_body_conn_close(w);
            }
            break;
        case HTTP_SECTION_REQ_RESP:
            if (dpi_is_client_pkt(p)) {
                FLAGS_SET(w->flags, HTTP_FLAGS_REQUEST);
                w->cmd_start = dpi_ptr_2_seq(p, ptr);
                w->hdr_start = 0;
                w->body_start = 0;
            } else {
                w->cmd_start = 0;
                w->hdr_start = 0;
                w->body_start = dpi_ptr_2_seq(p, ptr);
                FLAGS_UNSET(w->flags, HTTP_FLAGS_REQUEST);
            }
            if (unlikely(data->proto == HTTP_PROTO_RTSP)) {
                if (len <= 5) return;
                if (strncmp((char *)ptr, "RTSP/", 5) == 0) {
                    FLAGS_SET(w->flags, HTTP_FLAGS_REQUEST);
                } else {
                    FLAGS_UNSET(w->flags, HTTP_FLAGS_REQUEST);
                }
            }

            if (is_request(w)) {
                shift = http_parse_request(&ctx, ptr, len);
                if (shift == -1) {
                    dpi_fire_parser(p);
                    return;
                } else if (shift == 0) {
                    return;
                }

                dpi_finalize_parser(p);
            } else {
                shift = http_parse_response(&ctx, ptr, len);
                if (shift == -1) {
                    // Take all as body
                    w->section = HTTP_SECTION_BODY;
                    set_body_conn_close(w);
                } else if (shift == 0) {
                    return;
                }

                switch (data->proto) {
                case HTTP_PROTO_HTTP: overwrite_base_app(p, DPI_APP_HTTP); break;
                case HTTP_PROTO_RTSP: overwrite_base_app(p, DPI_APP_RTSP); break;
                case HTTP_PROTO_SIP:  overwrite_base_app(p, DPI_APP_SIP);  break;
                }
            }

            ptr += shift;
            len -= shift;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);
            if (shift > 0) {
                //offset to cmd_start
                w->hdr_start = w->seq;
                if (is_request(w)) {
                    dpi_dlp_area_t *dlparea = &p->dlp_area[DPI_SIG_CONTEXT_TYPE_URI_ORIGIN];
                    dlparea->dlp_start = w->cmd_start;
                    dlparea->dlp_end  = w->hdr_start;
                    dlparea->dlp_ptr = dpi_pkt_ptr(p) + dlparea->dlp_start - dpi_pkt_seq(p);
                    dlparea->dlp_offset = 0;
                    dlparea->dlp_len = dlparea->dlp_end - dlparea->dlp_start - dlparea->dlp_offset;
                }
            }

            w->section = HTTP_SECTION_HEADER;

            // Set short timeout to detect slowloris header attack
            if (is_request(w) && dpi_threat_status(DPI_THRT_HTTP_SLOWLORIS)) {
                DEBUG_LOG(DBG_SESSION | DBG_PARSER, p,
                          "Start HTTP slowerloris detection in header\n");

                data->url_start_tick = th_snap.tick;
                dpi_session_start_tick_for(s, DPI_SESS_TICK_FLAG_SLOWLORIS, p);
            }

            break;
        case HTTP_SECTION_HEADER:
            shift = http_parse_header(&ctx, ptr, len, &done);

            ptr += shift;
            len -= shift;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);

            p->dlp_area[DPI_SIG_CONTEXT_TYPE_HEADER].dlp_start = w->hdr_start;
            p->dlp_area[DPI_SIG_CONTEXT_TYPE_HEADER].dlp_end  = w->seq;

            if (!done) return;

            w->body_start = w->seq;
            w->section = HTTP_SECTION_FIRST_BODY;

            data->body_buffer_len = 0;

            // start slowloris body attack detection
            if (is_slowloris_on_for_wing(s, w)) {
                data->url_start_tick = 0;

                if (unlikely(to_detect_slowloris_body_attack(data, w))) {
                    DEBUG_LOG(DBG_SESSION | DBG_PARSER, p,
                              "Start HTTP slowerloris detection in body\n");

                    // Try to detect HTTP slowloris body attack. Between header and first body, 30s.
                    data->last_body_tick = th_snap.tick;
                } else {
                    DEBUG_LOG(DBG_SESSION | DBG_PARSER, p, "Stop HTTP slowerloris detection\n");

                    // stop slowloris detection
                    dpi_session_stop_tick_for(s, DPI_SESS_TICK_FLAG_SLOWLORIS, p);
                }
            }

            // If neither 'content-length' nor 'chunked' is set, take all the rest as body
            // unless we are sure the type of request or response has no body entity.
            if (unlikely(!(w->flags & (HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CHUNKED)))) {
                if (is_request(w)) {
                    if (data->method == HTTP_METHOD_GET) {
                    } else {
                        set_body_conn_close(w);
                    }
                } else {
                    if (data->method == HTTP_METHOD_HEAD || data->status == 204 ||
                        (data->status / 100 != 2 && data->status < 500)) { // 1xx, 3xx, 4xx
                    } else {
                        set_body_conn_close(w);
                    }
                }
            }

            // As body can be empty, we must let body parsing function run at least once
            // to complete state transition.

            // Fall through.
        case HTTP_SECTION_FIRST_BODY:
        case HTTP_SECTION_BODY:
            if (unlikely(is_slowloris_on_for_wing(s, w))) {
                data->last_body_tick = th_snap.tick;
            }

            shift = http_parse_body(&ctx, ptr, len, &done);
            if (shift == 0) {
                // This happens when http chunk length section doesn't give a full line.
                w->section = HTTP_SECTION_BODY;
                return;
            }

            ptr += shift;
            len -= shift;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);

            p->dlp_area[DPI_SIG_CONTEXT_TYPE_BODY].dlp_start = w->body_start;
            p->dlp_area[DPI_SIG_CONTEXT_TYPE_BODY].dlp_end  = w->seq;

            if (done) {
                if (unlikely(is_slowloris_on_for_wing(s, w))) {
                    dpi_session_stop_tick_for(s, DPI_SESS_TICK_FLAG_SLOWLORIS, p);
                }

                set_body_done(w);
                w->section = HTTP_SECTION_NONE;
            } else if (unlikely(w->section == HTTP_SECTION_FIRST_BODY)) {
                w->section = HTTP_SECTION_BODY;
            }

            break;
        }
    }
}

static void http_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void http_delete_data(void *data)
{
    free(((http_data_t *)data)->body_buffer);
    free(data);
}

static dpi_parser_t dpi_parser_http = {
    new_session: http_new_session,
    delete_data: http_delete_data,
    parser:      http_parser,
    name:        "http",
    ip_proto:    IPPROTO_TCP,
    type:        DPI_PARSER_HTTP,
};

dpi_parser_t *dpi_http_tcp_parser(void)
{
    int pcre_errno;
    PCRE2_SIZE pcre_erroroffset;

    if (apache_struts_re == NULL) {
        apache_struts_re = pcre2_compile((PCRE2_SPTR)APACHE_STRUTS_PCRE,
                                         PCRE2_ZERO_TERMINATED,
                                         0,
                                         &pcre_errno,
                                         &pcre_erroroffset,
                                         NULL);
        if (apache_struts_re == NULL) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(pcre_errno, buffer, sizeof(buffer));
            DEBUG_ERROR(DBG_PARSER, "ERROR: PCRE2 compilation for (%s) failed at offset %d: %s\n",
                                    APACHE_STRUTS_PCRE, pcre_errno, buffer);
        }
    }

    return &dpi_parser_http;
}
