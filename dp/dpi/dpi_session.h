#ifndef __DPI_SESSION_H__
#define __DPI_SESSION_H__

#include "utils/rcu_map.h"
#include "utils/helper.h"
#include "utils/asm.h"
#include "utils/bits.h"

#include "dpi/dpi_packet.h"
#include "dpi/dpi_policy.h"

#define DPI_WING_FLAG_FIN  0x01
#define DPI_WING_FLAG_SACK 0x02

typedef struct dpi_parser_ {
    void (*new_session) (dpi_packet_t *p);
    void (*delete_data) (void *data);
    void (*parser) (dpi_packet_t *p);
    void (*new_mid_sess) (dpi_packet_t *p);
    void (*midstream)   (dpi_packet_t *p);

    const char *name;
    uint8_t ip_proto, type;
} dpi_parser_t;

typedef struct dpi_wing_ {
    uint8_t mac[ETH_ALEN];
    uint16_t port;
    io_ip_t ip;
    uint32_t next_seq, init_seq;
    uint32_t asm_seq;

    union {
        struct {
            uint32_t tcp_acked;
            uint32_t tcp_win;
        };
        struct {
            uint32_t icmp_echo_hash;
            uint16_t icmp_echo_seq;
            uint8_t icmp_times;
        };
    };
    uint16_t tcp_mss;
    uint8_t tcp_state:  4,
            tcp_wscale: 4;
    uint8_t flags;
    asm_t asm_cache;
    uint32_t pkts, bytes;
    uint32_t reported_pkts, reported_bytes;
} dpi_wing_t;

#define DPI_SESS_FLAG_IPV4               0x0001
#define DPI_SESS_FLAG_SKIP_PARSER        0x0002
#define DPI_SESS_FLAG_FINAL_PARSER       0x0004
#define DPI_SESS_FLAG_LAST_PARSER        0x0008
#define DPI_SESS_FLAG_INGRESS            0x0010
#define DPI_SESS_FLAG_TAP                0x0020
#define DPI_SESS_FLAG_MID_STREAM         0x0040
#define DPI_SESS_FLAG_FAKE_EP            0x0080
#define DPI_SESS_FLAG_ESTABLISHED        0x0100  // Session has been in established state
#define DPI_SESS_FLAG_POLICY_APP_READY   0x0200  // Session has app ready for policy eval
#define DPI_SESS_FLAG_START_LOGGED       0x0400  // Session start has been logged
#define DPI_SESS_FLAG_SCAN               0x0800
#define DPI_SESS_FLAG_IGNOR_PATTERN      0x1000
#define DPI_SESS_FLAG_XFF                0x2000
#define DPI_SESS_FLAG_PROXYMESH          0x4000

#define DPI_SESS_FLAG_ONLY_PARSER (DPI_SESS_FLAG_FINAL_PARSER | DPI_SESS_FLAG_LAST_PARSER)
// Either app is ID-ed, or no app can be ID-ed.
// This is mostly used to see if log should be sent or not. One difference between this
// and APP_READY is, for a mid-stream session, if app cannot be ID-ed, APP_READY will be
// false so no re-eval but SURE_PARSER is true so mid-session log keeps sending.
#define DPI_SESS_FLAG_SURE_PARSER (DPI_SESS_FLAG_FINAL_PARSER | DPI_SESS_FLAG_SKIP_PARSER)

// 4bits in session
#define DPI_SESS_TICK_FLAG_SMALL_WINDOWS  0x1
#define DPI_SESS_TICK_FLAG_SLOWLORIS      0x2

// 4bits in session
#define DPI_SESS_METER_FLAG_IP_SESSION    0x1

enum {
    DPI_SESS_TICK_CONTINUE = 0,
    DPI_SESS_TICK_STOP,
    DPI_SESS_TICK_RESET,
};

enum {
    DPI_SESS_TERM_NORMAL = 0,
    DPI_SESS_TERM_VOLUME,
    DPI_SESS_TERM_THREAT,
    DPI_SESS_TERM_POLICY,
    DPI_SESS_TERM_DLP,
};

typedef struct dpi_session_ {
    struct cds_lfht_node node;
    timer_entry_t ts_entry;
    timer_entry_t tick_entry;

    uint32_t id;
    uint32_t created_at;
    uint32_t last_report;

    dpi_wing_t client, server;
    void *parser_data[DPI_PARSER_MAX];

    uint16_t flags;
    uint8_t tick_flags :4,
            meter_flags:4;
    uint8_t only_parser;

    uint32_t small_window_tick; // small window size start tick

    BITMASK_DEFINE(parser_bits, DPI_PARSER_MAX);

    uint16_t app, base_app;
    uint8_t ip_proto;
    uint8_t action:      3,
            severity:    3,
            term_reason: 2;
    uint32_t threat_id;
    dpi_policy_desc_t policy_desc;
    dpi_policy_desc_t xff_desc;
    BITOP tags;
    uint32_t xff_client_ip;
    uint16_t xff_app;
    uint16_t xff_port;
} dpi_session_t;

static inline uint32_t dpi_wing_length(const dpi_wing_t *wing)
{
    return u32_distance(wing->init_seq, wing->next_seq);
}

void dpi_session_release(dpi_session_t *s);
void dpi_session_timeout(timer_entry_t *n);
void dpi_session_term_reason(dpi_session_t *s, int term);

extern uint32_t g_sess_id_to_clear;
extern struct ether_addr *g_mac_addr_to_del;
void dpi_session_delete(dpi_session_t *s, int reason);

void dpi_proto_parser(dpi_packet_t *p);
void dpi_midstream_proto_praser(dpi_packet_t *p);
void dpi_recruit_parser(dpi_packet_t *p);
void dpi_midstream_recruit_parser(dpi_packet_t *p);
void *dpi_get_parser_data(dpi_packet_t *p);
void dpi_put_parser_data(dpi_packet_t *p, void *data);
void dpi_hire_parser(dpi_packet_t *p);
void dpi_fire_parser(dpi_packet_t *p);
void dpi_ignore_parser(dpi_packet_t *p);
void dpi_set_asm_seq(dpi_packet_t *p, uint32_t seq);
bool dpi_is_parser_final(dpi_packet_t *p);
void dpi_finalize_parser(dpi_packet_t *p);
void dpi_purge_parser_data(dpi_session_t *s);

void dpi_asm_remove(clip_t *clip);
int dpi_cache_packet(dpi_packet_t *p, dpi_wing_t *w, bool lookup);

io_app_t *dpi_ep_app_map_lookup(io_ep_t *ep, uint16_t port, uint8_t ip_proto);
void dpi_ep_set_proto(dpi_packet_t *p, uint16_t proto);
void dpi_ep_set_app(dpi_packet_t *p, uint16_t server, uint16_t application);
void dpi_ep_set_server_ver(dpi_packet_t *p, char *ver, int len);
uint16_t dpi_ep_get_app(dpi_packet_t *p);
bool dpi_is_base_app(uint16_t app);

void dpi_inject_reset(dpi_packet_t *p, bool to_server);
void dpi_inject_reset_by_session(dpi_session_t *s, bool to_server);
void dpi_session_start_tick_for(dpi_session_t *s, uint8_t flag, dpi_packet_t *p);
void dpi_session_stop_tick_for(dpi_session_t *s, uint8_t flag, dpi_packet_t *p);

static inline bool dpi_session_check_tick(dpi_session_t *s, int tick_flag)
{
    return !!(s->tick_flags & tick_flag);
}

static inline void dpi_session_set_tick(dpi_session_t *s, int tick_flag)
{
    s->tick_flags |= tick_flag;
}

static inline void dpi_session_unset_tick(dpi_session_t *s, int tick_flag)
{
    s->tick_flags &= ~tick_flag;
}

void dpi_catch_stats_slot(io_stats_t *stats, uint32_t slot);
void dpi_inc_stats_packet(dpi_packet_t *p);
void dpi_inc_stats_session(dpi_packet_t *p, dpi_session_t *s);
void dpi_dec_stats_session(dpi_session_t *s);

int dpi_http_tick_timeout(dpi_session_t *s, void *parser_data);

const char *dpi_get_tcp_state_name(int state);

void dpi_session_init(void);
void dpi_session_proxymesh_init(void);
void dpi_session_trim(void);

int dpi_sess_policy_reeval(dpi_session_t *s);
#endif
