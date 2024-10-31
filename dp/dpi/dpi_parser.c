#include <string.h>

#include "dpi/dpi_module.h"

int dpi_parser_2_app[DPI_PARSER_MAX] = {
[DPI_PARSER_HTTP] = DPI_APP_HTTP,
[DPI_PARSER_SSL] = DPI_APP_SSL,
[DPI_PARSER_SSH] = DPI_APP_SSH,
[DPI_PARSER_DNS] = DPI_APP_DNS,
[DPI_PARSER_DHCP] = DPI_APP_DHCP,
[DPI_PARSER_NTP] = DPI_APP_NTP,
[DPI_PARSER_TFTP] = DPI_APP_TFTP,
[DPI_PARSER_ECHO] = DPI_APP_ECHO,
[DPI_PARSER_MYSQL] = DPI_APP_MYSQL,
[DPI_PARSER_REDIS] = DPI_APP_REDIS,
[DPI_PARSER_ZOOKEEPER] = DPI_APP_ZOOKEEPER,
[DPI_PARSER_CASSANDRA] = DPI_APP_CASSANDRA,
[DPI_PARSER_MONGODB] = DPI_APP_MONGODB,
[DPI_PARSER_POSTGRESQL] = DPI_APP_POSTGRESQL,
[DPI_PARSER_KAFKA] = DPI_APP_KAFKA,
[DPI_PARSER_COUCHBASE] = DPI_APP_COUCHBASE,
[DPI_PARSER_SPARK] = DPI_APP_SPARK,
[DPI_PARSER_TNS] = DPI_APP_TNS,
[DPI_PARSER_TDS] = DPI_APP_TDS,
[DPI_PARSER_GRPC] = DPI_APP_GRPC,
};

dpi_parser_t *g_tcp_parser[DPI_PARSER_MAX];
dpi_parser_t *g_udp_parser[DPI_PARSER_MAX];
dpi_parser_t *g_any_parser[DPI_PARSER_MAX];

bool dpi_is_base_app(uint16_t app)
{
    return app < DPI_APP_PROTO_MARK;
}

static dpi_parser_t **get_parser_list(int ip_proto)
{
    switch (ip_proto) {
    case IPPROTO_TCP:
        return g_tcp_parser;
    case IPPROTO_UDP:
        return g_udp_parser;
    default:
        return g_any_parser;
    }
}

// Called by protocol parser
inline void *dpi_get_parser_data(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    return s->parser_data[p->cur_parser->type];
}

inline void dpi_put_parser_data(dpi_packet_t *p, void *data)
{
    dpi_session_t *s = p->session;
    s->parser_data[p->cur_parser->type] = data;
}

// Called when parser loses interest of the session
static void dpi_delete_parser_data(dpi_session_t *s, dpi_parser_t *cp)
{
    if (cp->delete_data != NULL && s->parser_data[cp->type] != NULL) {
        cp->delete_data(s->parser_data[cp->type]);
    }
    s->parser_data[cp->type] = NULL;
}

// Called when session is released
void dpi_purge_parser_data(dpi_session_t *s)
{
    dpi_parser_t **list = get_parser_list(s->ip_proto);
    int t;

    for (t = 0; t < DPI_PARSER_MAX; t ++) {
        if (list[t] != NULL) {
            dpi_delete_parser_data(s, list[t]);
        }
    }
}

// Called by protocol parser
inline void dpi_hire_parser(dpi_packet_t *p)
{
    DEBUG_LOG(DBG_PARSER, p, "%s\n", p->cur_parser->name);

    dpi_session_t *s = p->session;
    BITMASK_SET(s->parser_bits, p->cur_parser->type);
}

inline void dpi_fire_parser(dpi_packet_t *p)
{
    DEBUG_LOG(DBG_PARSER, p, "%s\n", p->cur_parser->name);

    dpi_session_t *s = p->session;
    BITMASK_UNSET(s->parser_bits, p->cur_parser->type);
}

// It's intentional to keep this as a separate function from 'fire'.
// 'ignore' is used in the case where the session type is finalized,
// but the parser won't be at work.
inline void dpi_ignore_parser(dpi_packet_t *p)
{
    DEBUG_LOG(DBG_PARSER, p, "%s\n", p->cur_parser->name);

    dpi_session_t *s = p->session;
    BITMASK_UNSET(s->parser_bits, p->cur_parser->type);
}

inline void dpi_set_asm_seq(dpi_packet_t *p, uint32_t seq)
{
    p->parser_asm_seq = seq;
} 

inline bool dpi_is_parser_final(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    return !!(s->flags & DPI_SESS_FLAG_FINAL_PARSER);
}

void dpi_finalize_parser(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;

    if (dpi_is_parser_final(p)) return;

    DEBUG_LOG(DBG_SESSION, p, "sess %u, %s\n", s->id, p->cur_parser->name);

    s->flags |= DPI_SESS_FLAG_FINAL_PARSER;
    s->only_parser = p->cur_parser->type;

    uint16_t app = dpi_parser_2_app[s->only_parser];
    if (dpi_is_base_app(app)) {
        if (s->base_app == 0) {
            s->base_app = app;
            dpi_ep_set_proto(p, app);
        }
    } else {
        s->app = app;
        dpi_ep_set_app(p, 0, app);
    }

    s->flags |= DPI_SESS_FLAG_POLICY_APP_READY;

    dpi_parser_t **list = get_parser_list(s->ip_proto);
    dpi_parser_t *saved_parser = p->cur_parser;
    int t;

    for (t = 0; t < DPI_PARSER_MAX; t ++) {
        if (t != saved_parser->type && BITMASK_TEST(s->parser_bits, t)) {
            p->cur_parser = list[t];
            dpi_fire_parser(p);
            dpi_delete_parser_data(s, p->cur_parser);
        }
    }

    // 'parser_left' will be increased after the parser if it's not ignored.
    p->parser_left = 0;
    p->cur_parser = saved_parser;

    // Discard asm_seq of previous parsers. This is called from the parser, the current
    // parser's asm_seq will be set after parsing.
    p->asm_seq = p->this_wing->next_seq;
}

void dpi_recruit_parser(dpi_packet_t *p)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PACKET | DBG_PARSER, p);

    dpi_parser_t **list = get_parser_list(p->ip_proto), *cp;
    int t;

    for (t = 0; t < DPI_PARSER_MAX; t ++) {
        cp = p->cur_parser = list[t];
        if (cp != NULL && cp->new_session != NULL) {
            cp->new_session(p);
        }
    }
}

void dpi_midstream_recruit_parser(dpi_packet_t *p)
{
    dpi_parser_t **list = get_parser_list(p->ip_proto), *cp;
    int t;

    for (t = 0; t < DPI_PARSER_MAX; t ++) {
        cp = p->cur_parser = list[t];
        if (cp != NULL && cp->midstream != NULL && cp->new_mid_sess != NULL) {
            DEBUG_LOG(DBG_PARSER, p, "new mid session parser: %s\n", cp->name);
            cp->new_mid_sess(p);
        }
    }
}

void dpi_proto_parser(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    dpi_parser_t **list = get_parser_list(p->ip_proto), *cp;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, p);

    if (p->flags & DPI_PKT_FLAG_ASSEMBLED) {
        p->pkt_buffer = &p->asm_pkt;
    }

    // Set asm_seq to the lastest possible, and set per-parser one the earliest.
    p->asm_seq = p->this_wing->next_seq;

    if (s->flags & DPI_SESS_FLAG_ONLY_PARSER) {
        cp = p->cur_parser = list[s->only_parser];
        if (cp != NULL && cp->parser != NULL) {
            DEBUG_LOG(DBG_PARSER, p, "%s: %s\n",
                      (s->flags & DPI_SESS_FLAG_FINAL_PARSER) ? "final" : "last", cp->name);

            // Reset per-parser asm_seq to the earliest.
            p->parser_asm_seq = p->this_wing->asm_seq;
            cp->parser(p);

            if (!BITMASK_TEST(s->parser_bits, s->only_parser)) {
                DEBUG_LOG(DBG_SESSION, p, "sess %u: skip parser\n", s->id);
                dpi_delete_parser_data(s, cp);
                s->flags |= DPI_SESS_FLAG_SKIP_PARSER;
                s->flags &= ~DPI_SESS_FLAG_ONLY_PARSER;
                s->flags |= DPI_SESS_FLAG_POLICY_APP_READY;
            }

            // Cache the earliest asm_seq
            if (u32_lt(p->parser_asm_seq, p->asm_seq)) {
                p->asm_seq = p->parser_asm_seq;
            }
        }
    } else {
        int t, last = 0;

        // Walk through all parsers
        p->parser_left = 0;
        for (t = 0; t < DPI_PARSER_MAX; t ++) {
            cp = p->cur_parser = list[t];
            if (cp != NULL && cp->parser != NULL && BITMASK_TEST(s->parser_bits, t)) {
                DEBUG_LOG(DBG_PARSER, p, "parse: %s\n", cp->name);

                p->parser_asm_seq = p->this_wing->asm_seq;
                cp->parser(p);

                if (BITMASK_TEST(s->parser_bits, t)) {
                    p->parser_left ++;
                    last = t;

                    // Cache the earliest asm_seq
                    if (u32_lt(p->parser_asm_seq, p->asm_seq)) {
                        p->asm_seq = p->parser_asm_seq;
                    }
                } else {
                    dpi_delete_parser_data(s, cp);
                }
            }
        }

        switch (p->parser_left) {
        case 0:
            // Session can still be finalized (protocol recognized) when we reach here - the
            // parser confirms the session type but is not interested in the session any more.
            DEBUG_LOG(DBG_SESSION, p, "sess %u: skip parser\n", s->id);
            s->flags |= DPI_SESS_FLAG_SKIP_PARSER;
            s->flags |= DPI_SESS_FLAG_POLICY_APP_READY;
            break;
        case 1:
            DEBUG_LOG(DBG_PARSER, p, "Last parser: %s\n", list[last]->name);
            s->flags |= DPI_SESS_FLAG_LAST_PARSER;
            s->only_parser = last;
            break;
        }
    }

    p->this_wing->asm_seq = p->asm_seq;

    if (p->flags & DPI_PKT_FLAG_ASSEMBLED) {
        p->pkt_buffer = &p->raw;
    }
}

void dpi_midstream_proto_praser(dpi_packet_t *p) {
    dpi_session_t *s = p->session;
    dpi_parser_t **list = get_parser_list(p->ip_proto), *cp;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, p);

    if (s->flags & DPI_SESS_FLAG_ONLY_PARSER) {
        cp = p->cur_parser = list[s->only_parser];
        if (cp != NULL && cp->parser != NULL) {
            cp->midstream(p);
        }
        if (!BITMASK_TEST(s->parser_bits, s->only_parser)) {
            DEBUG_LOG(DBG_PARSER, p, "Mid stream Skip parsers,sesssion id=%d\n", p->session->id);
            s->flags |= DPI_SESS_FLAG_SKIP_PARSER;
            s->flags &= ~DPI_SESS_FLAG_ONLY_PARSER;
        }
    } else {
        int t, last = 0;

        p->parser_left = 0;
        for (t = 0; t < DPI_PARSER_MAX; t ++) {
            cp = p->cur_parser = list[t];
            if (cp != NULL && cp->midstream != NULL) {
                DEBUG_LOG(DBG_PARSER, p, "Check mid stream %s\n", cp->name);
                cp->midstream(p);
                if (BITMASK_TEST(s->parser_bits, t)) {
                    p->parser_left ++;
                    last = t;
                }
            }
        }
        switch (p->parser_left) {
        case 0:
            // It's possible that session is and will still be finalized.
            DEBUG_LOG(DBG_PARSER, p, "Skip mid stream parsers\n");
            s->flags |= DPI_SESS_FLAG_SKIP_PARSER;
            /*
             * For mid stream packet, since app may not be identified,
             * policy will not be reevaled if app cannot be identified - NVSHAS-315
             */
            break;
        case 1:
            DEBUG_LOG(DBG_PARSER, p, "Last mid stream parser: %s\n", list[last]->name);
            s->flags |= DPI_SESS_FLAG_LAST_PARSER;
            s->only_parser = last;
            break;
        }
    }
}
// ----

extern dpi_parser_t *dpi_dhcp_parser(void);
extern dpi_parser_t *dpi_dns_tcp_parser(void);
extern dpi_parser_t *dpi_dns_udp_parser(void);
extern dpi_parser_t *dpi_http_tcp_parser(void);
extern dpi_parser_t *dpi_ssh_parser(void);
extern dpi_parser_t *dpi_ssl_parser(void);
extern dpi_parser_t *dpi_mysql_parser(void);
extern dpi_parser_t *dpi_redis_parser(void);
extern dpi_parser_t *dpi_zookeeper_tcp_parser(void);
extern dpi_parser_t *dpi_zookeeper_udp_parser(void);
extern dpi_parser_t *dpi_cassandra_parser(void);
extern dpi_parser_t *dpi_mongodb_parser(void);
extern dpi_parser_t *dpi_postgresql_parser(void);
extern dpi_parser_t *dpi_kafka_parser(void);
extern dpi_parser_t *dpi_couchbase_parser(void);
extern dpi_parser_t *dpi_tftp_udp_parser(void);
extern dpi_parser_t *dpi_ntp_udp_parser(void);
extern dpi_parser_t *dpi_echo_tcp_parser(void);
extern dpi_parser_t *dpi_echo_udp_parser(void);
extern dpi_parser_t *dpi_spark_parser(void);
extern dpi_parser_t *dpi_tns_tcp_parser(void);
extern dpi_parser_t *dpi_tds_tcp_parser(void);
extern dpi_parser_t *dpi_grpc_tcp_parser(void);

static void register_parser(dpi_parser_t *parser)
{
    dpi_parser_t **list = get_parser_list(parser->ip_proto);
    list[parser->type] = parser;
}

void dpi_parser_setup(void)
{
    register_parser(dpi_dhcp_parser());
    register_parser(dpi_dns_tcp_parser());
    register_parser(dpi_dns_udp_parser());
    register_parser(dpi_http_tcp_parser());
    register_parser(dpi_ssh_parser());
    register_parser(dpi_ssl_parser());
    register_parser(dpi_mysql_parser());
    register_parser(dpi_redis_parser());
    register_parser(dpi_zookeeper_tcp_parser());
    register_parser(dpi_zookeeper_udp_parser());
    register_parser(dpi_cassandra_parser());
    register_parser(dpi_mongodb_parser());
    register_parser(dpi_postgresql_parser());
    register_parser(dpi_kafka_parser());
    register_parser(dpi_couchbase_parser());
    register_parser(dpi_tftp_udp_parser());
    register_parser(dpi_ntp_udp_parser());
    register_parser(dpi_echo_tcp_parser());
    register_parser(dpi_echo_udp_parser());
    register_parser(dpi_spark_parser());
    register_parser(dpi_tns_tcp_parser());
    register_parser(dpi_tds_tcp_parser());
    register_parser(dpi_grpc_tcp_parser());
}
