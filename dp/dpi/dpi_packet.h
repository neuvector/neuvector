#ifndef __DPI_PACKET_H__
#define __DPI_PACKET_H__

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "utils/helper.h"
#include "dpi/sig/dpi_sig.h"

#define DPI_MAX_PKT_LEN 65536

typedef enum dpi_tcp_options_ {
    TCP_OPT_EOL = 0,
    TCP_OPT_NOP,
    TCP_OPT_MSS,
    TCP_OPT_WSCALE,
    TCP_OPT_SACKOK,
    TCP_OPT_SACK,
    TCP_OPT_ECHO,
    TCP_OPT_ECHOREPLY,
    TCP_OPT_TIMESTAMP,
    TCP_OPT_PARTIAL_PERM,
    TCP_OPT_PARTIAL_SVC,
    TCP_OPT_CC,
    TCP_OPT_CC_NEW,
    TCP_OPT_CC_ECHO,
    TCP_OPT_ALTCSUM_ALGO,
    TCP_OPT_ALTCSUM_DATA,
    TCP_OPT_SKEETER,
    TCP_OPT_BUBBA,
    TCP_OPT_TRAILER_CSUM,
    TCP_OPT_MD5,
    TCP_OPT_SCPS,
    TCP_OPT_SELNEGACK,
    TCP_OPT_RECORDBOUND,
    TCP_OPT_CORRUPTION,
    TCP_OPT_SNAP,
    TCP_OPT_UNASSIGNED,
    TCP_OPT_COMPRESSION,
    TCP_OPT_MAX,
} dpi_tcp_options_t;

#define DPI_PKT_FLAG_SACKOK        0x00000001
#define DPI_PKT_FLAG_TCP_TS        0x00000002
#define DPI_PKT_FLAG_CLIENT        0x00000004
#define DPI_PKT_FLAG_NEW_SESSION   0x00000008
#define DPI_PKT_FLAG_ASSEMBLED     0x00000010
#define DPI_PKT_FLAG_CACHED        0x00000020
#define DPI_PKT_FLAG_SKIP_PARSER   0x00000040
#define DPI_PKT_FLAG_SKIP_PATTERN  0x00000080
#define DPI_PKT_FLAG_INGRESS       0x00000100
#define DPI_PKT_FLAG_FAKE_EP       0x00000200
#define DPI_PKT_FLAG_NOT_USED      0x00000400
#define DPI_PKT_FLAG_LOG_MID       0x00000800
#define DPI_PKT_FLAG_LOG_VIOLATE   0x00001000
#define DPI_PKT_FLAG_LOG_XFF       0x00002000
#define DPI_PKT_FLAG_LOG_XFF_VIO   0x00004000
#define DPI_PKT_FLAG_DETECT_DLP    0x00008000
#define DPI_PKT_FLAG_DETECT_WAF    0x00010000

#define DPI_MAX_MATCH_RESULT     16
#define DPI_MAX_MATCH_CANDIDATE  256
#define DPI_MAX_ICMP_TYPE  256

struct dpi_wing_;
struct dpi_session_;
struct dpi_parser_;

#define DPI_FIELD_FLAG_NON_PKT_BUFFER     0x01

typedef struct dpi_dlp_area_ {
    uint8_t *dlp_ptr;        // starting position
    uint32_t dlp_len;        // length of the area
    uint32_t dlp_start;      // start of seqnum
    uint32_t dlp_end;        // end of seqnum
    uint32_t dlp_offset;
    uint8_t dlp_flags;
} dpi_dlp_area_t;

typedef struct dpi_match_ {
    dpi_sig_user_t *user;
    uint32_t dlp_match_seq;
    uint8_t dlp_match_flags;
} dpi_match_t;

typedef struct dpi_match_candidate_ {
    dpi_sig_user_t *user;
    bool nc;
} dpi_match_candidate_t;

typedef struct dpi_packet_ {
    uint8_t *pkt;

    struct ip6_frag *ip6_fragh;

    uint32_t flags;

    struct dpi_session_ *session;
    struct dpi_wing_ *this_wing, *that_wing;

    uint16_t l2;
    uint16_t l3;
    uint16_t l4;
    uint16_t cap_len;
    uint16_t len;
    uint16_t eth_type;
    uint16_t sport, dport;
    uint8_t ip_proto;

    uint8_t tcp_wscale;
    uint16_t tcp_mss;
    uint32_t tcp_ts_value, tcp_ts_echo;

    uint32_t threat_id;
    uint8_t action:   3,
            severity: 3;  // record packet threat severity when session is not located, ex. ping death
    uint8_t pad[3];

    void *frag_trac;
    void *cached_clip;

    uint32_t EOZ;

    uint64_t id;
    struct dpi_parser_ *cur_parser;
    buf_t *pkt_buffer;
    buf_t raw;
    buf_t asm_pkt;
    uint8_t *defrag_data;
    uint32_t asm_seq, parser_asm_seq; // cache asm_seq during protocol parsing

    io_ctx_t *ctx;
    io_ep_t *ep;
    uint8_t *ep_mac;
    io_stats_t *ep_stats;
    io_metry_t *ep_all_metry;
    io_metry_t *ep_app_metry;
    io_stats_t *stats;
    io_metry_t *all_metry;
    io_metry_t *app_metry;

    uint8_t parser_left;
    /*dlp related*/
    uint32_t dlp_match_seq;
    dpi_sig_context_type_t dlp_match_type;
    dpi_sig_context_type_t dlp_pat_context;
    uint8_t dlp_match_flags;
    dpi_dlp_area_t dlp_area[DPI_SIG_CONTEXT_TYPE_MAX];
    buf_t decoded_pkt;

    uint8_t dlp_candidates_overflow;
    uint8_t has_dlp_candidates;

    int dlp_results;
    int dlp_candidates;
    dpi_match_t dlp_match_results[DPI_MAX_MATCH_RESULT];
    dpi_match_candidate_t dlp_match_candidates[DPI_MAX_MATCH_CANDIDATE];
} dpi_packet_t;

static inline uint8_t *dpi_pkt_ptr(dpi_packet_t *p)
{
    return p->pkt_buffer->ptr;
}

static inline uint8_t *dpi_pkt_end(dpi_packet_t *p)
{
    return p->pkt_buffer->ptr + p->pkt_buffer->len;
}

static inline uint32_t dpi_pkt_seq(dpi_packet_t *p)
{
    return p->pkt_buffer->seq;
}

static inline uint32_t dpi_pkt_len(dpi_packet_t *p)
{
    return p->pkt_buffer->len;
}

static inline uint32_t dpi_pkt_end_seq(dpi_packet_t *p)
{
    return p->pkt_buffer->seq + dpi_pkt_len(p);
}

static inline uint16_t get_iph_len(struct iphdr *iph)
{
    return iph->ihl << 2;
}

static inline uint16_t get_tcph_len(struct tcphdr *tcph)
{
    return tcph->doff << 2;
}

static inline bool dpi_is_ipv4(dpi_packet_t *p)
{
    return p->eth_type == ETH_P_IP;
}

static inline void dpi_set_client_pkt(dpi_packet_t *p)
{
    p->flags |= DPI_PKT_FLAG_CLIENT;
}

static inline bool dpi_is_client_pkt(dpi_packet_t *p)
{
    return (p->flags & DPI_PKT_FLAG_CLIENT) ? true : false;
}

static inline bool dpi_is_seq_in_pkt(dpi_packet_t *p, uint32_t seq)
{
    return u32_distance(dpi_pkt_seq(p), seq) < dpi_pkt_len(p);
}

static inline uint32_t dpi_ptr_2_seq(dpi_packet_t *p, uint8_t *ptr)
{
    return dpi_pkt_seq(p) + (ptr - dpi_pkt_ptr(p));
}

uint16_t get_l4v6_cksum(struct ip6_hdr *ip6h, uint8_t ip_proto, void *l4_hdr, uint16_t l4_len);
uint16_t get_l4v4_cksum(struct iphdr *iph, void *l4_hdr, uint16_t l4_len);
uint16_t get_ip_cksum(struct iphdr *iph);
char *get_tcp_flag_string(struct tcphdr *tcph, char *s);

void dpi_set_action(dpi_packet_t *p, int act);
bool dpi_is_action_final(dpi_packet_t *p, int act);
int dpi_parse_ethernet(dpi_packet_t *p);
int dpi_inspect_ethernet(dpi_packet_t *p);

void dpi_frag_init(void);
void dpi_frag_send(void *frag_trac, io_ctx_t *ctx);
void dpi_frag_discard(void *frag_trac);
void dpi_frag_trim(void);
int dpi_ip_defrag(dpi_packet_t *p);
int dpi_ipv6_defrag(dpi_packet_t *p);

bool dpi_is_ip4_internal(uint32_t ip);
uint8_t dpi_ip4_iptype(uint32_t ip);
bool dpi_is_policy_addr(uint32_t ip);

#endif
