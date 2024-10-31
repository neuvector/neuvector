#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

typedef struct redis_wing_ {
    uint32_t seq;
} redis_wing_t;

typedef struct redis_data_ {
    redis_wing_t client, server;
    bool  has_client_hdr;
} redis_data_t;

//static void print_redis(uint8_t * ptr, uint32_t len)
//{
//    uint8_t * p = ptr;
//    int i;
//
//    for(i=0; i< len; i++) {
//        if ( *p == '\r')
//           printf("\\r");
//        else if ( *p == '\n')
//           printf("\\n");
//        else
//           printf("%c",*p);
//        p++;
//    }
//    printf("\n");
//}

static inline bool is_redis_head(uint8_t *ptr)
{
    return *ptr == '*' ||
           *ptr == '+' ||
           *ptr == '-' ||
           *ptr == '$' ||
           *ptr == ':' ;
}

static inline bool is_redis_end(uint8_t *ptr, uint32_t len)
{
    return ((*(ptr+len-2)) == '\r') && ((*(ptr+len-1)) == '\n');
}

//return 0 : not enough data
//       1 : redis client header
//       -1: not redis client header
static int is_redis_client_hdr(uint8_t *ptr,uint32_t len)
{
    uint8_t *p = ptr;
    uint32_t l = len, str_cnt=0;

    if (len < 8) {
        return 0;
    }

    //the first redis client packet should an array start with * and number
    if ((*p++) != '*') {
        return -1;
    }

    l--;
    while (*p >= '0' && *p <= '9' && l > 0) {
        str_cnt++;
        p++;
        l--;
    }

    if (l < 6) {
        return 0;
    }

    if (str_cnt > 9 || str_cnt == 0 || ((*p != '\r') || (*(p+1) != '\n'))) {
        return -1;
    }

    p+=2;
    l-=2;

    //the following should be the charater number of the first string start with $
    if (*p != '$') {
        return -1;
    }

    str_cnt = 0;
    p++;
    l--;

    while (*p >= '0' && *p <= '9' && l > 0) {
        str_cnt++;
        p++;
        l--;
    }

    if (l < 2) {
        return 0;
    }

    if (str_cnt > 9 || str_cnt == 0 || ((*p != '\r') || (*(p+1) != '\n'))) {
        return -1;
    }

    return 1;
}

static void redis_parser(dpi_packet_t *p)
{
    redis_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not REDIS: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }

        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }

        data->has_client_hdr = false;
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    redis_wing_t *w;
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

    //check redis client request
    if (dpi_is_client_pkt(p)) {
        if (data->has_client_hdr) {
            w->seq += len;
            dpi_set_asm_seq(p, w->seq);
        }
        else {
            int res = is_redis_client_hdr(ptr,len);
            if (res == 1) {
                DEBUG_LOG(DBG_PARSER, p, "REDIS: First client packet parse finish\n");
                data->has_client_hdr = true;

                w->seq += len;
                dpi_set_asm_seq(p, w->seq);
            }
            else if (res == -1) {
                DEBUG_LOG(DBG_PARSER, p, "Not REDIS client packet header\n");
                dpi_fire_parser(p);
            }
        }
    }
    else {
        if (is_redis_head(ptr) && data->has_client_hdr) {
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "REDIS server header\n");
        }
        else {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_PARSER, p, "Not REDIS server\n");
        }
    }
}

static void redis_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void redis_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_redis = {
    .new_session = redis_new_session,
    .delete_data = redis_delete_data,
    .parser = redis_parser,
    .name = "redis",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_REDIS,
};

dpi_parser_t *dpi_redis_parser(void)
{
    return &dpi_parser_redis;
}
