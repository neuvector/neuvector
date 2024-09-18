#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "utils/helper.h"

#include "dpi/dpi_log.h"

extern bool cmp_mac_prefix(void *m1, void *prefix);
extern int g_stats_slot;

#define LOG_CACHE_TIMEOUT 5

typedef struct log_cache_ {
    struct cds_lfht_node node;
    timer_entry_t ts_entry;

    DPMsgThreatLog log;
    uint32_t count;
    uint32_t last_log;
} log_cache_t;

typedef struct threat_property_ {
    uint32_t id;
    uint8_t severity;
    uint8_t volume :1,
            ddos   :1;
    uint32_t freq;
} threat_property_t;

typedef struct threat_config_ {
    bool enable;
    uint8_t action;
} threat_config_t;

// Threat attributes are separated into two places. Eventually they will be generated from a single source
static threat_property_t threat_property[] = {
[DPI_THRT_NONE]              {0, },
[DPI_THRT_TCP_FLOOD]         {THRT_ID_SYN_FLOOD, THRT_SEVERITY_CRITICAL, 1, 1, 10, },
[DPI_THRT_ICMP_FLOOD]        {THRT_ID_ICMP_FLOOD, THRT_SEVERITY_CRITICAL, 1, 1, 10, },
[DPI_THRT_IP_SRC_SESSION]    {THRT_ID_IP_SRC_SESSION, THRT_SEVERITY_HIGH, 1, 1, 10, },
[DPI_THRT_BAD_PACKET]        {THRT_ID_BAD_PACKET, THRT_SEVERITY_MEDIUM, 0, 0, 10, },
[DPI_THRT_IP_TEARDROP]       {THRT_ID_IP_TEARDROP, THRT_SEVERITY_CRITICAL, 0, 1, 10, },
[DPI_THRT_TCP_SYN_DATA]      {THRT_ID_TCP_SYN_DATA, THRT_SEVERITY_MEDIUM, 0, 0, 10, },
[DPI_THRT_TCP_SPLIT_HDSHK]   {THRT_ID_TCP_SPLIT_HDSHK, THRT_SEVERITY_MEDIUM, 0, 0, 10, },
[DPI_THRT_TCP_NODATA]        {THRT_ID_TCP_NODATA, THRT_SEVERITY_MEDIUM, 0, 1, 10, },
[DPI_THRT_TCP_SMALL_WINDOW]  {THRT_ID_TCP_SMALL_WINDOW, THRT_SEVERITY_HIGH, 0, 1, 10, },
[DPI_THRT_TCP_SMALL_MSS]     {THRT_ID_TCP_SMALL_MSS, THRT_SEVERITY_HIGH, 0, 0, 10, },
[DPI_THRT_PING_DEATH]        {THRT_ID_PING_DEATH, THRT_SEVERITY_CRITICAL, 0, 0, (uint32_t)(-1), },
[DPI_THRT_DNS_LOOP_PTR]      {THRT_ID_DNS_LOOP_PTR, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_SSH_VER_1]         {THRT_ID_SSH_VER_1, THRT_SEVERITY_LOW, 0, 0, 10, },
[DPI_THRT_SSL_HEARTBLEED]    {THRT_ID_SSL_HEARTBLEED, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_SSL_CIPHER_OVF]    {THRT_ID_SSL_CIPHER_OVF, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_SSL_VER_2OR3]      {THRT_ID_SSL_VER_2OR3, THRT_SEVERITY_MEDIUM, 0, 0, 10, },
[DPI_THRT_SSL_TLS_1DOT0]     {THRT_ID_SSL_TLS_1DOT0, THRT_SEVERITY_INFO, 0, 0, 10, },
[DPI_THRT_HTTP_NEG_LEN]      {THRT_ID_HTTP_NEG_LEN, THRT_SEVERITY_HIGH, 0, 0, 10, },
[DPI_THRT_HTTP_SMUGGLING]    {THRT_ID_HTTP_SMUGGLING, THRT_SEVERITY_HIGH, 0, 0, 10, },
[DPI_THRT_HTTP_SLOWLORIS]    {THRT_ID_HTTP_SLOWLORIS, THRT_SEVERITY_CRITICAL, 0, 1, 10, },
[DPI_THRT_DNS_OVERFLOW]      {THRT_ID_DNS_OVERFLOW, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_MYSQL_ACCESS_DENY] {THRT_ID_MYSQL_ACCESS_DENY, THRT_SEVERITY_INFO, 0, 0, 10, },
[DPI_THRT_DNS_ZONE_TRANSFER] {THRT_ID_DNS_ZONE_TRANSFER, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_ICMP_TUNNELING]    {THRT_ID_ICMP_TUNNELING, THRT_SEVERITY_CRITICAL, 0, 0, (uint32_t)(-1), },
[DPI_THRT_DNS_TYPE_NULL]     {THRT_ID_DNS_TYPE_NULL, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_SQL_INJECTION]     {THRT_ID_SQL_INJECTION, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_APACHE_STRUTS_RCE] {THRT_ID_APACHE_STRUTS_RCE, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_K8S_EXTIP_MITM]    {THRT_ID_K8S_EXTIP_MITM, THRT_SEVERITY_CRITICAL, 0, 0, 10, },
[DPI_THRT_SSL_TLS_1DOT1]     {THRT_ID_SSL_TLS_1DOT1, THRT_SEVERITY_INFO, 0, 0, 10, },
};

static threat_config_t threat_config[] = {
[DPI_THRT_NONE]             {false, DPI_ACTION_NONE, },
[DPI_THRT_TCP_FLOOD]        {true, DPI_ACTION_DROP, },
[DPI_THRT_ICMP_FLOOD]       {true, DPI_ACTION_DROP, },
[DPI_THRT_IP_SRC_SESSION]   {false, DPI_ACTION_DROP, },
[DPI_THRT_BAD_PACKET]       {true, DPI_ACTION_DROP, },
[DPI_THRT_IP_TEARDROP]      {true, DPI_ACTION_DROP, },
[DPI_THRT_TCP_SYN_DATA]     {false, DPI_ACTION_DROP, }, // Some load balancer has the behavior
[DPI_THRT_TCP_SPLIT_HDSHK]  {true, DPI_ACTION_ALLOW, },
[DPI_THRT_TCP_NODATA]       {false, DPI_ACTION_RESET, }, // FIXME: disabled because tap rx is prone to packet loss
[DPI_THRT_TCP_SMALL_WINDOW] {false, DPI_ACTION_RESET, },
[DPI_THRT_TCP_SMALL_MSS]    {true, DPI_ACTION_DROP, },
[DPI_THRT_PING_DEATH]       {true, DPI_ACTION_DROP, },
[DPI_THRT_DNS_LOOP_PTR]     {true, DPI_ACTION_DROP, },
[DPI_THRT_SSH_VER_1]        {true, DPI_ACTION_ALLOW, },
[DPI_THRT_SSL_HEARTBLEED]   {true, DPI_ACTION_DROP, },
[DPI_THRT_SSL_CIPHER_OVF]   {true, DPI_ACTION_DROP, },
[DPI_THRT_SSL_VER_2OR3]     {true, DPI_ACTION_DROP, },
[DPI_THRT_SSL_TLS_1DOT0]    {false, DPI_ACTION_ALLOW, },
[DPI_THRT_HTTP_NEG_LEN]     {true, DPI_ACTION_DROP, },
[DPI_THRT_HTTP_SMUGGLING]   {true, DPI_ACTION_DROP, },
[DPI_THRT_HTTP_SLOWLORIS]   {false, DPI_ACTION_RESET, }, // FIXME: disabled because tap rx is prone to packet loss
[DPI_THRT_DNS_OVERFLOW]     {true, DPI_ACTION_ALLOW, }, // FIXME: Make it drop
[DPI_THRT_MYSQL_ACCESS_DENY]{true, DPI_ACTION_ALLOW, },
[DPI_THRT_DNS_ZONE_TRANSFER]{true, DPI_ACTION_DROP,  },
[DPI_THRT_ICMP_TUNNELING]   {true, DPI_ACTION_ALLOW, },
[DPI_THRT_DNS_TYPE_NULL]    {false, DPI_ACTION_ALLOW, },
[DPI_THRT_SQL_INJECTION]    {true, DPI_ACTION_DROP, },
[DPI_THRT_APACHE_STRUTS_RCE]{true, DPI_ACTION_DROP, },
[DPI_THRT_K8S_EXTIP_MITM]   {true, DPI_ACTION_DROP, },
[DPI_THRT_SSL_TLS_1DOT1]    {false, DPI_ACTION_ALLOW, },
};

static int log_dlp_match(struct cds_lfht_node *ht_node, const void *key)
{
    log_cache_t *c = STRUCT_OF(ht_node, log_cache_t, node);
    const DPMsgThreatLog *k = key;

    return (c->log.DlpNameHash == k->DlpNameHash && c->log.Flags == k->Flags &&
            memcmp(c->log.EPMAC, k->EPMAC, sizeof(k->EPMAC)) == 0) ? true : false;
}

static int log_match(struct cds_lfht_node *ht_node, const void *key)
{
    log_cache_t *c = STRUCT_OF(ht_node, log_cache_t, node);
    const DPMsgThreatLog *k = key;

    if (k->ThreatID > DPI_SIG_MIN_USER_SIG_ID) {
        return log_dlp_match(ht_node, key);
    }

    return (c->log.ThreatID == k->ThreatID && c->log.Flags == k->Flags &&
            memcmp(c->log.EPMAC, k->EPMAC, sizeof(k->EPMAC)) == 0) ? true : false;
}

static uint32_t log_dlp_hash(const void *key)
{
    const DPMsgThreatLog *k = key;

    return sdbm_hash((uint8_t *)k->EPMAC, sizeof(k->EPMAC)) + k->DlpNameHash;
}

static uint32_t log_hash(const void *key)
{
    const DPMsgThreatLog *k = key;

    if (k->ThreatID > DPI_SIG_MIN_USER_SIG_ID) {
        return log_dlp_hash(key);
    }

    return sdbm_hash((uint8_t *)k->EPMAC, sizeof(k->EPMAC)) + k->ThreatID;
}

static void log_release(timer_entry_t *entry)
{
    log_cache_t *c = STRUCT_OF(entry, log_cache_t, ts_entry);

    if (c->count > 0) {
        DEBUG_LOG(DBG_LOG, NULL, "id=%u count=%u\n", ntohl(c->log.ThreatID), c->count);
        c->log.Count = htonl(c->count);
        c->log.ReportedAt = htonl(time(NULL));
        // Threat report at cache timeout contain the latest packet content
        g_io_callback->threat_log(&c->log);
    }

    th_counter.cur_log_caches --;
    rcu_map_del(&th_log_map, c);
    free(c);
}

void dpi_log_init(void)
{
    if (g_io_config->thrt_ssl_tls_1dot0)
    {
        dpi_set_threat_status(DPI_THRT_SSL_TLS_1DOT0, true);
    }
    if (g_io_config->thrt_ssl_tls_1dot1)
    {
        dpi_set_threat_status(DPI_THRT_SSL_TLS_1DOT1, true);
    }
    
    rcu_map_init(&th_log_map, 128, offsetof(log_cache_t, node), log_match, log_hash);
}

static inline uint16_t session_app(dpi_session_t *sess)
{
    if (sess->app > 0) return sess->app;
    return sess->base_app;
}

void log_common(DPMsgThreatLog *log, int idx)
{
    log->ThreatID = htonl(threat_property[idx].id);
    log->Action = threat_config[idx].action;
    log->Severity = threat_property[idx].severity;
    log->ReportedAt = htonl(time(NULL));
}

void log_packet_flags(DPMsgThreatLog *log, dpi_packet_t *p, bool flip)
{
    if (p->ep->tap) {
        log->Flags |= DPLOG_FLAG_TAP;
    }
    if ((p->flags & DPI_PKT_FLAG_INGRESS)) {
        if (likely(!flip)) log->Flags |= DPLOG_FLAG_PKT_INGRESS;
    } else {
        if (unlikely(flip)) log->Flags |= DPLOG_FLAG_PKT_INGRESS;
    }
    if (likely(p->session != NULL)) {
        if (FLAGS_TEST(p->session->flags, DPI_SESS_FLAG_INGRESS)) {
            FLAGS_SET(log->Flags, DPLOG_FLAG_SESS_INGRESS);
        }
    }
}

void log_proxymesh_packet_detail(DPMsgThreatLog *log, dpi_packet_t *p, bool flip)
{
    dpi_wing_t *s = &(p->session->server);

    // l2
    log->EtherType = htons(p->eth_type);

    // l3
    if (likely(p->l3 > 0)) {
        log->IPProto = p->ip_proto;
        if (likely(!flip)) {
            if (likely(p->eth_type == ETH_P_IP)) {
                struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
                ip4_cpy(log->SrcIP, (uint8_t *)&iph->saddr);
                ip4_cpy(log->DstIP, (uint8_t *)&s->ip.ip4);
            } else {
                struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
                memcpy(log->SrcIP, &ip6h->ip6_src, sizeof(log->SrcIP));
                memcpy(log->DstIP, &s->ip.ip6, sizeof(log->DstIP));
            }
        } else {
            if (likely(p->eth_type == ETH_P_IP)) {
                struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
                ip4_cpy(log->SrcIP, (uint8_t *)&s->ip.ip4);
                ip4_cpy(log->DstIP, (uint8_t *)&iph->saddr);
            } else {
                struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
                memcpy(log->SrcIP, &s->ip.ip6, sizeof(log->DstIP));
                memcpy(log->DstIP, &ip6h->ip6_src, sizeof(log->SrcIP));
            }
        }
    }

    // l4
    if (likely(p->l4 > 0)) {
        //struct icmphdr *icmph;
        //struct icmp6_hdr *icmp6h;

        switch (p->ip_proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            if (likely(!flip)) {
                log->SrcPort = htons(p->sport);
                log->DstPort = htons(s->port);
            } else {
                log->SrcPort = htons(s->port);
                log->DstPort = htons(p->sport);
            }
            break;
        case IPPROTO_ICMP:
            log->ICMPCode = (s->port & 0xff);
            log->ICMPType = (s->port >> 8) & 0xff;
            break;
        case IPPROTO_ICMPV6:
            log->ICMPCode = (s->port & 0xff);
            log->ICMPType = (s->port >> 8) & 0xff;
            break;
        }
    }

    if (likely(p->session != NULL)) {
        log->Application = htons(session_app(p->session));
    }
}

void log_packet_detail(DPMsgThreatLog *log, dpi_packet_t *p, bool flip)
{
    // l2
    log->EtherType = htons(p->eth_type);

    // l3
    if (likely(p->l3 > 0)) {
        log->IPProto = p->ip_proto;
        if (likely(!flip)) {
            if (likely(p->eth_type == ETH_P_IP)) {
                struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
                ip4_cpy(log->SrcIP, (uint8_t *)&iph->saddr);
                ip4_cpy(log->DstIP, (uint8_t *)&iph->daddr);
            } else {
                struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
                memcpy(log->SrcIP, &ip6h->ip6_src, sizeof(log->SrcIP));
                memcpy(log->DstIP, &ip6h->ip6_dst, sizeof(log->DstIP));
            }
        } else {
            if (likely(p->eth_type == ETH_P_IP)) {
                struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
                ip4_cpy(log->SrcIP, (uint8_t *)&iph->daddr);
                ip4_cpy(log->DstIP, (uint8_t *)&iph->saddr);
            } else {
                struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
                memcpy(log->SrcIP, &ip6h->ip6_dst, sizeof(log->DstIP));
                memcpy(log->DstIP, &ip6h->ip6_src, sizeof(log->SrcIP));
            }
        }
    }

    // l4
    if (likely(p->l4 > 0)) {
        struct icmphdr *icmph;
        struct icmp6_hdr *icmp6h;

        switch (p->ip_proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            if (likely(!flip)) {
                log->SrcPort = htons(p->sport);
                log->DstPort = htons(p->dport);
            } else {
                log->SrcPort = htons(p->dport);
                log->DstPort = htons(p->sport);
            }
            break;
        case IPPROTO_ICMP:
            icmph = (struct icmphdr *)(p->pkt + p->l4);
            log->ICMPCode = icmph->code;
            log->ICMPType = icmph->type;
            break;
        case IPPROTO_ICMPV6:
            icmp6h = (struct icmp6_hdr *)(p->pkt + p->l4);
            log->ICMPCode = icmp6h->icmp6_code;
            log->ICMPType = icmp6h->icmp6_type;
            break;
        }
    }

    if (likely(p->session != NULL)) {
        log->Application = htons(session_app(p->session));
    }
}

void log_session_flags(DPMsgThreatLog *log, dpi_session_t *sess)
{
    if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_TAP)) {
        FLAGS_SET(log->Flags, DPLOG_FLAG_TAP);
    }
    if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_INGRESS)) {
        FLAGS_SET(log->Flags, DPLOG_FLAG_SESS_INGRESS|DPLOG_FLAG_PKT_INGRESS);
    }
}

void log_session_detail(DPMsgThreatLog *log, dpi_session_t *sess)
{
    dpi_wing_t *c = &sess->client, *s = &sess->server;

    // l3
    {
        log->IPProto = sess->ip_proto;
        if (likely(sess->flags & DPI_SESS_FLAG_IPV4)) {
            log->EtherType = htons(ETH_P_IP);
            ip4_cpy(log->SrcIP, (uint8_t *)&c->ip.ip4);
            ip4_cpy(log->DstIP, (uint8_t *)&s->ip.ip4);
        } else {
            log->EtherType = htons(ETH_P_IPV6);
            memcpy(&log->SrcIP, &c->ip.ip6, sizeof(log->SrcIP));
            memcpy(&log->DstIP, &s->ip.ip6, sizeof(log->DstIP));
        }
    }

    // l4
    {
        switch (sess->ip_proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            log->SrcPort = htons(c->port);
            log->DstPort = htons(s->port);
            break;
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            log->ICMPCode = s->port & 0xff;
            log->ICMPType = (s->port >> 8) & 0xff;
            break;
        }
    }

    log->Application = htons(session_app(sess));
}

static log_cache_t *add_cache(DPMsgThreatLog *log, DPMsgThreatLog *key)
{
    log_cache_t *cache = calloc(1, sizeof(*cache));
    if (cache != NULL) {
        memcpy(&cache->log, log, sizeof(*log));
        cache->last_log = th_snap.tick;
        rcu_map_add(&th_log_map, cache, key);
        th_counter.cur_log_caches ++;

        timer_wheel_entry_init(&cache->ts_entry);
        timer_wheel_entry_start(&th_timer, &cache->ts_entry,
                                log_release, LOG_CACHE_TIMEOUT, th_snap.tick);
    }

    return cache;
}

// return count to be logged
static uint32_t update_cache(log_cache_t *cache, threat_property_t *tprop)
{
    timer_wheel_entry_refresh(&th_timer, &cache->ts_entry, th_snap.tick);

    if (th_snap.tick - cache->last_log < tprop->freq) {
        cache->count ++;
        return 0;
    } else {
        uint32_t count = cache->count + 1;
        cache->count = 0;
        cache->last_log = th_snap.tick;
        // continue logging with new packet data
        return count;
    }
}

bool dpi_threat_status(uint32_t idx)
{
    if (unlikely(idx >= DPI_THRT_MAX)) return false;
    return threat_config[idx].enable;
}

void dpi_set_threat_status(uint32_t idx, bool enable)
{
    if (unlikely(idx >= DPI_THRT_MAX) || unlikely(idx < DPI_THRT_NONE)) return;
    threat_config[idx].enable = enable;
}

uint8_t dpi_threat_action(uint32_t idx)
{
    if (unlikely(idx >= DPI_THRT_MAX)) return DPI_ACTION_ALLOW;
    return threat_config[idx].action;
}

static void store_packet(DPMsgThreatLog *log, dpi_packet_t *p)
{
    log->CapLen = htons(p->cap_len);
    if (likely(p->cap_len < DPLOG_MAX_PKT_LEN)) {
        memcpy(log->Packet, p->pkt, p->cap_len);
        log->PktLen = htons(p->cap_len);
    } else {
        memcpy(log->Packet, p->pkt, DPLOG_MAX_PKT_LEN);
        log->PktLen = htons(DPLOG_MAX_PKT_LEN);
    }

    // Recover MAC address
    if (likely(p->cap_len >= sizeof(struct ethhdr))) {
        struct ethhdr *eth = (struct ethhdr *)(log->Packet + p->l2);
        if FLAGS_TEST(p->flags, DPI_PKT_FLAG_INGRESS) {
            mac_cpy(eth->h_dest, p->ep_mac);
        } else {
            mac_cpy(eth->h_source, p->ep_mac);
        }
    }
}

static void dpi_threat_trigger_dir(uint32_t idx, dpi_packet_t *p, bool flip, const char *format, va_list args)
{
    DPMsgThreatLog log;
    uint32_t count = 1;

    if (!dpi_threat_status(idx)) return;

    threat_property_t *tprop = &threat_property[idx];
    threat_config_t *tconf = &threat_config[idx];

    uint8_t action = tconf->action;
    dpi_set_action(p, action);

    // Look for cache
    memset(&log, 0, sizeof(log));
    log.ThreatID = htonl(tprop->id);
    if (unlikely(p->ep_mac == NULL)) return;
    mac_cpy(log.EPMAC, p->ep_mac);
    log_packet_flags(&log, p, flip);

    if (tprop->severity > p->severity) {
        // Keep threat's severity in case session doesn't exist
        p->threat_id = tprop->id;
        p->severity = tprop->severity;
        // Don't set LOG_MID because this doesn't mean session severity level changed
    }

    if (likely(p->session != NULL)) {
        dpi_session_t *sess = p->session;

        if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_INGRESS)) {
            FLAGS_SET(log.Flags, DPLOG_FLAG_SESS_INGRESS);
        }

        if (action == DPI_ACTION_RESET || action == DPI_ACTION_DROP) {
            dpi_session_term_reason(sess, DPI_SESS_TERM_THREAT);
        }
        if (tprop->severity > sess->severity) {
            sess->threat_id = tprop->id;
            sess->severity = tprop->severity;
            FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_MID);
        }
    }

    IF_DEBUG_LOG(DBG_LOG, p) {
        DEBUG_LOG_NO_FILTER("id=%u action=%s ", tprop->id, debug_action_name(tconf->action));
        debug_dump_packet_short(p);
    }

    log_cache_t *cache = rcu_map_lookup(&th_log_map, &log);
    if (cache != NULL) {
        if ((count = update_cache(cache, tprop)) == 0) {
            // aggregated, store the latest packet
            store_packet(&cache->log, p);
            return;
        }
    }

    log_common(&log, idx);
    log.Count = htonl(count);
    log_packet_detail(&log, p, flip);
    vsnprintf(log.Msg, sizeof(log.Msg), format, args);
    store_packet(&log, p);

    DEBUG_LOG(DBG_LOG, p, "id=%u count=%u\n", tprop->id, count);

    if (cache == NULL) {
        cache = add_cache(&log, &log);
    } else {
        // Update log data in cache
        memcpy(&cache->log, &log, sizeof(log));
    }

    g_io_callback->threat_log(&log);
}

void dpi_threat_trigger(uint32_t idx, dpi_packet_t *p, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    dpi_threat_trigger_dir(idx, p, false, format, args);
    va_end(args);
}

void dpi_threat_trigger_flip(uint32_t idx, dpi_packet_t *p, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    dpi_threat_trigger_dir(idx, p, true, format, args);
    va_end(args);
}

static void dpi_dlp_trigger_sig_dir(dpi_packet_t *p, dpi_match_t *m, bool flip, const char *format, va_list args)
{
    dpi_sig_user_t *user = m->user;
    dpi_sig_t *sig = user->sig;
    threat_property_t tprop;
    DPMsgThreatLog log;
    uint32_t count = 1;
    uint8_t action;
    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);
    
    memset(&tprop, 0, sizeof(tprop));

    tprop.freq = 10;
    tprop.id = sig->sig_id;
    tprop.severity = user->severity;

    action = user->action;

    // Look for cache
    memset(&log, 0, sizeof(log));
    log.ThreatID = htonl(tprop.id);
    log.DlpNameHash = sdbm_hash((uint8_t *)(sig->conf->name), strlen(sig->conf->name)*sizeof(char));

    if (unlikely(p->ep_mac == NULL)) return;
    mac_cpy(log.EPMAC, p->ep_mac);
    log_packet_flags(&log, p, flip);

    if (tprop.severity > p->severity) {
        // Keep threat's severity in case session doesn't exist
        p->threat_id = tprop.id;
        p->severity = tprop.severity;
    }

    if (likely(p->session != NULL)) {
        dpi_session_t *sess = p->session;

        if (action == DPI_ACTION_DROP) {
            dpi_session_term_reason(sess, DPI_SESS_TERM_DLP);
        }
        if (tprop.severity > sess->severity) {
            sess->threat_id = tprop.id;
            sess->severity = tprop.severity;
            FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_MID);
        }
    }

    log_cache_t *cache = rcu_map_lookup(&th_log_map, &log);
    if (cache != NULL) {
        if ((count = update_cache(cache, &tprop)) == 0) {
            // aggregated, store the latest packet
            store_packet(&cache->log, p);
            return;
        }
    }

    log.Action = user->action;
    log.Severity = tprop.severity;
    log.ReportedAt = htonl(time(NULL));
    log.Count = htonl(count);
    //for service mesh's egress session, egress packet's dst ip/port come from sess  
    if (isproxymesh && !(p->flags & DPI_PKT_FLAG_INGRESS) && 
        (p->session && !FLAGS_TEST(p->session->flags, DPI_SESS_FLAG_INGRESS))) {
        log_proxymesh_packet_detail(&log, p, flip);
    } else {
        log_packet_detail(&log, p, flip);
    }

    if (format) {
        vsnprintf(log.Msg, sizeof(log.Msg), format, args);
    }
    store_packet(&log, p);

    DEBUG_LOG(DBG_LOG, p, "id=%u count=%u msg=%s\n", tprop.id, count, log.Msg);

    if (cache == NULL) {
        cache = add_cache(&log, &log);
    } else {
        // Update log data in cache
        memcpy(&cache->log, &log, sizeof(log));
    }

    g_io_callback->threat_log(&log);
}

void dpi_dlp_log_by_sig(dpi_packet_t *p, dpi_match_t *m, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    dpi_dlp_trigger_sig_dir(p, m, false, format, args);
    va_end(args);
}

void dpi_threat_log_by_session(uint32_t idx, dpi_session_t *sess, const char *format, ...)
{
    DPMsgThreatLog log;
    dpi_wing_t *c = &sess->client, *s = &sess->server;
    uint32_t count = 1;

    if (unlikely(idx >= DPI_THRT_MAX)) return;

    threat_property_t *tprop = &threat_property[idx];
    threat_config_t *tconf = &threat_config[idx];
    uint8_t action = tconf->action;

    // Look for cache
    memset(&log, 0, sizeof(log));
    log.ThreatID = htonl(tprop->id);
    if (sess->flags & DPI_SESS_FLAG_INGRESS) {
        mac_cpy(log.EPMAC, s->mac);
    } else {
        mac_cpy(log.EPMAC, c->mac);
    }
    log_session_flags(&log, sess);

    if (action == DPI_ACTION_RESET || action == DPI_ACTION_DROP) {
        dpi_session_term_reason(sess, DPI_SESS_TERM_THREAT);
    }
    if (tprop->severity > sess->severity) {
        sess->threat_id = tprop->id;
        sess->severity = tprop->severity;
    }

    IF_DEBUG_LOG(DBG_LOG, NULL) {
        DEBUG_LOG_NO_FILTER("id=%u action=%s ", tprop->id, debug_action_name(tconf->action));
        debug_dump_session_short(sess);
    }

    log_cache_t *cache = rcu_map_lookup(&th_log_map, &log);
    if (cache != NULL) {
        if ((count = update_cache(cache, tprop)) == 0) {
            // aggregated
            return;
        }
    }

    log_common(&log, idx);
    log.Count = htonl(count);
    log_session_detail(&log, sess);
    if (format != NULL) {
        va_list args;
        va_start(args, format);
        vsnprintf(log.Msg, sizeof(log.Msg), format, args);
        va_end(args);
    }

    DEBUG_LOG(DBG_LOG, NULL, "id=%u count=%u\n", tprop->id, count);

    if (cache == NULL) {
        cache = add_cache(&log, &log);
    } else {
        // Update log data in cache
        memcpy(&cache->log, &log, sizeof(log));
    }

    g_io_callback->threat_log(&log);
}

static void dump_meter_short(const dpi_meter_t *m)
{
    if (likely(m->log.EtherType == ntohs(ETH_P_IP))) {
        debug_log(false, DBG_IPV4_FORMAT, DBG_IPV4_TUPLE(m->peer_ip.ip4));
    } else {
        debug_log(false, DBG_IPV6_FORMAT, DBG_IPV6_TUPLE(m->peer_ip.ip6));
    }
    debug_log(false, " -> "DBG_MAC_FORMAT"\n", DBG_MAC_TUPLE(m->ep_mac));
}

void dpi_ddos_log(uint32_t idx, dpi_meter_t *m, const char *format, ...)
{
    DPMsgThreatLog *log = &m->log;

    mac_cpy(log->EPMAC, m->ep_mac);
    log->Count = htonl(m->log_count);
    if (format != NULL) {
        va_list args;
        va_start(args, format);
        vsnprintf(log->Msg, sizeof(log->Msg), format, args);
        va_end(args);
    }

    IF_DEBUG_LOG(DBG_LOG, NULL) {
        DEBUG_LOG_NO_FILTER("id=%u count=%u ", idx, m->log_count);
        dump_meter_short(m);
    }

    g_io_callback->threat_log(log);
}

int dpi_session_log_xff(dpi_session_t *s, DPMsgSession *dps)
{
    //replace client ip with xff_client_ip to learn policy
    if (likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_IPV4))) {
        //xff is always detected on sess_ingress direction
        dps->Flags |= DPSESS_FLAG_INGRESS;
        mac_cpy(dps->EPMAC, s->server.mac);
        ip4_cpy(dps->ClientIP, (uint8_t *)&s->xff_client_ip);
        if (s->xff_desc.flags & POLICY_DESC_EXTERNAL) {
            dps->Flags |= DPSESS_FLAG_EXTERNAL;
        }
        dps->Flags |= DPSESS_FLAG_XFF;
        dps->Application = s->xff_app;
        dps->ServerPort = s->xff_port;
        dps->PolicyAction = s->xff_desc.action;
        dps->PolicyId = s->xff_desc.id;
    } else {//no need to send a duplicate connect report if not ipv4
        return -1;
    }
    return 0;
}

static void get_ingress_stats(DPMonitorMetric *dpm, io_stats_t *s)
{
    uint32_t cur = g_stats_slot;
    uint32_t last = s->cur_slot;
    register uint32_t i, n;
    register uint32_t sess;
    register uint64_t byte;

    // 12x5s
    if (last + 12 >= cur) {
        uint32_t from = (cur >= 12) ? cur - 12 : 0;
        sess = 0;
        byte = 0;
        for (n = from; n < last; n ++) {
            i = n % STATS_SLOTS;
            sess += s->in.sess_ring[i];
            byte += s->in.byte_ring[i];
        }
        dpm->EpSessIn12 = sess;
        dpm->EpByteIn12 = byte;
    }
    dpm->EpSessCurIn = s->in.cur_session;
}

void dpi_session_log(dpi_session_t *sess, DPMsgSession *dps, DPMonitorMetric *dpm)
{
    memset(dps, 0, sizeof(DPMsgSession));

    dpi_wing_t *c = &sess->client, *s = &sess->server;

    dps->ID = sess->id;

    dps->Flags = 0;
    if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_INGRESS)) {
        dps->Flags |= DPSESS_FLAG_INGRESS;
        mac_cpy(dps->EPMAC, s->mac);
    } else {
        mac_cpy(dps->EPMAC, c->mac);
    }

    mac_cpy(dps->ClientMAC, c->mac);
    mac_cpy(dps->ServerMAC, s->mac);

    if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_TAP)) {
        dps->Flags |= DPSESS_FLAG_TAP;
    }
    if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_MID_STREAM)) {
        dps->Flags |= DPSESS_FLAG_MID;
    }

    if (likely(FLAGS_TEST(sess->flags, DPI_SESS_FLAG_IPV4))) {
        dps->EtherType = ETH_P_IP;
        ip4_cpy(dps->ClientIP, (uint8_t *)&c->ip.ip4);
        ip4_cpy(dps->ServerIP, (uint8_t *)&s->ip.ip4);
        if (sess->policy_desc.flags & POLICY_DESC_EXTERNAL) {
            dps->Flags |= DPSESS_FLAG_EXTERNAL;
        }
        if (sess->policy_desc.flags & POLICY_DESC_SVC_EXTIP) {
            dps->Flags |= DPSESS_FLAG_SVC_EXTIP;
        }
        if (FLAGS_TEST(sess->flags, DPI_SESS_FLAG_XFF)) {
            ip4_cpy(dps->XffIP, (uint8_t *)&sess->xff_client_ip);
            dps->XffApp = sess->xff_app;
            dps->XffPort = sess->xff_port;
        }
        if (sess->policy_desc.flags & POLICY_DESC_MESH_TO_SVR) {
            dps->Flags |= DPSESS_FLAG_MESH_TO_SVR;
        }
        if (sess->policy_desc.flags & POLICY_DESC_LINK_LOCAL) {
            dps->Flags |= DPSESS_FLAG_LINK_LOCAL;
        }
        if (sess->policy_desc.flags & POLICY_DESC_TMP_OPEN) {
            dps->Flags |= DPSESS_FLAG_TMP_OPEN;
        }
        if (sess->policy_desc.flags & POLICY_DESC_UWLIP) {
            dps->Flags |= DPSESS_FLAG_UWLIP;
        }
        if (sess->policy_desc.flags & POLICY_DESC_CHK_NBE) {
            dps->Flags |= DPSESS_FLAG_CHK_NBE;
        }
        if (sess->policy_desc.flags & POLICY_DESC_NBE_SNS) {
            dps->Flags |= DPSESS_FLAG_NBE_SNS;
        }
    } else {
        dps->EtherType = ETH_P_IPV6;
        memcpy(dps->ClientIP, &c->ip.ip6, 16);
        memcpy(dps->ServerIP, &s->ip.ip6, 16);
    }
    dps->Application = session_app(sess);
    dps->IPProto = sess->ip_proto;
    switch (sess->ip_proto) {
    case IPPROTO_TCP:
        dps->ClientAsmPkts = asm_count(&c->asm_cache);
        dps->ServerAsmPkts = asm_count(&s->asm_cache);
        dps->ClientAsmBytes = asm_gross(&c->asm_cache);
        dps->ServerAsmBytes = asm_gross(&s->asm_cache);
        // Fall through
    case IPPROTO_UDP:
        dps->ClientPort = c->port;
        dps->ServerPort = s->port;
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        dps->ICMPCode = s->port & 0xff;
        dps->ICMPType = (s->port >> 8) & 0xff;
        break;
    }

    dps->ClientPkts = c->pkts;
    dps->ClientBytes = c->bytes;
    dps->ClientState = c->tcp_state;
    dps->ServerPkts = s->pkts;
    dps->ServerBytes = s->bytes;
    dps->ServerState = s->tcp_state;
    dps->Age = th_snap.tick - sess->created_at;
    dps->Idle = timer_wheel_entry_get_idle(&sess->ts_entry, th_snap.tick);
    dps->Life = timer_wheel_entry_get_life(&sess->ts_entry, th_snap.tick);

    dps->ThreatID = sess->threat_id;
    dps->Severity = sess->severity;
    dps->PolicyAction = sess->policy_desc.action;
    dps->PolicyId = sess->policy_desc.id;

    if (dpm == NULL) {
        return;
    }

    memset(dpm, 0, sizeof(DPMonitorMetric));
    io_mac_t *mac = rcu_map_lookup(&g_ep_map, dps->EPMAC);
    if (mac != NULL) {
        get_ingress_stats(dpm, &mac->ep->stats);
        /*DEBUG_LOG(DBG_LOG, NULL, "EpSessCurIn(%lu) EpSessIn12(%lu) EpByteIn12(%llu)\n",
        dpm->EpSessCurIn, dpm->EpSessIn12, dpm->EpByteIn12);*/
    }
}

static void dpi_session_log_from_pkt(dpi_packet_t *p, int to_server, dpi_policy_desc_t *desc,
                                     DPMsgSession *dps)
{
    memset(dps, 0, sizeof(DPMsgSession));
    mac_cpy(dps->EPMAC, p->ep_mac);

    struct ethhdr *eth = (struct ethhdr *)(p->pkt + p->l2);
    if (p->flags & DPI_PKT_FLAG_INGRESS) {
        if (likely(to_server)) {
            dps->Flags |= DPSESS_FLAG_INGRESS;
            mac_cpy(dps->ClientMAC, eth->h_source);
            mac_cpy(dps->ServerMAC, p->ep_mac);
        } else {
            mac_cpy(dps->ClientMAC, p->ep_mac);
            mac_cpy(dps->ServerMAC, eth->h_dest);
        }
    } else {
        if (likely(to_server)) {
            mac_cpy(dps->ClientMAC, eth->h_source);
            mac_cpy(dps->ServerMAC, p->ep_mac);
        } else {
            dps->Flags |= DPSESS_FLAG_INGRESS;
            mac_cpy(dps->ClientMAC, p->ep_mac);
            mac_cpy(dps->ServerMAC, eth->h_dest);
        }
    }
    if (p->ep->tap) {
        dps->Flags |= DPLOG_FLAG_TAP;
    }

    if (likely(dpi_is_ipv4(p))) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);

        dps->EtherType = ETH_P_IP;
        if (likely(to_server)) {
            ip4_cpy(dps->ClientIP, (uint8_t *)&iph->saddr);
            ip4_cpy(dps->ServerIP, (uint8_t *)&iph->daddr);
            dps->ClientPkts = 1;
            dps->ClientBytes = p->len;
        } else {
            ip4_cpy(dps->ClientIP, (uint8_t *)&iph->daddr);
            ip4_cpy(dps->ServerIP, (uint8_t *)&iph->saddr);
            dps->ServerPkts = 1;
            dps->ServerBytes = p->len;
        }

        /* triggered from violation, so policy must have been looked up */
        if (desc->flags & POLICY_DESC_EXTERNAL) {
            dps->Flags |= DPSESS_FLAG_EXTERNAL;
        }
        if (desc->flags & POLICY_DESC_SVC_EXTIP) {
            dps->Flags |= DPSESS_FLAG_SVC_EXTIP;
        }
        if (desc->flags & POLICY_DESC_MESH_TO_SVR) {
            dps->Flags |= DPSESS_FLAG_MESH_TO_SVR;
        }
        if (desc->flags & POLICY_DESC_LINK_LOCAL) {
            dps->Flags |= DPSESS_FLAG_LINK_LOCAL;
        }
        if (desc->flags & POLICY_DESC_TMP_OPEN) {
            dps->Flags |= DPSESS_FLAG_TMP_OPEN;
        }
        if (desc->flags & POLICY_DESC_UWLIP) {
            dps->Flags |= DPSESS_FLAG_UWLIP;
        }
        if (desc->flags & POLICY_DESC_CHK_NBE) {
            dps->Flags |= DPSESS_FLAG_CHK_NBE;
        }
        if (desc->flags & POLICY_DESC_NBE_SNS) {
            dps->Flags |= DPSESS_FLAG_NBE_SNS;
        }
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
        dps->EtherType = ETH_P_IPV6;
        if (likely(to_server)) {
            memcpy(dps->ClientIP, &ip6h->ip6_src, sizeof(dps->ClientIP));
            memcpy(dps->ServerIP, &ip6h->ip6_dst, sizeof(dps->ServerIP));
            dps->ClientPkts = 1;
            dps->ClientBytes = p->len;
        } else {
            memcpy(dps->ClientIP, &ip6h->ip6_dst, sizeof(dps->ClientIP));
            memcpy(dps->ServerIP, &ip6h->ip6_src, sizeof(dps->ServerIP));
            dps->ServerPkts = 1;
            dps->ServerBytes = p->len;
        }
    }

    dps->IPProto = p->ip_proto;
    switch (p->ip_proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        if (likely(to_server)) {
            dps->ClientPort = p->sport;
            dps->ServerPort = p->dport;
        } else {
            dps->ClientPort = p->dport;
            dps->ServerPort = p->sport;
        }
        break;
    case IPPROTO_ICMP:
        if (likely(to_server)) {
            dps->ICMPCode = p->dport & 0xff;
            dps->ICMPType = (p->dport >> 8) & 0xff;
        } else {
            dps->ICMPCode = p->sport & 0xff;
            dps->ICMPType = (p->sport >> 8) & 0xff;
        }
        break;
    }

    dps->ThreatID = p->threat_id;
    dps->Severity = p->severity;
    dps->PolicyAction = desc->action;
    dps->PolicyId = desc->id;
    // Only when there is no session, this function will be called.
    // For this case, mark the app as DPI_APP_NOT_CHECKED
    dps->Application = DPI_APP_NOT_CHECKED;
}

void dpi_policy_violate_log(dpi_packet_t *p, bool to_server,
                            dpi_policy_desc_t *desc)
{
    DPMsgSession dps;
    DPMonitorMetric dpm;

    IF_DEBUG_LOG(DBG_PACKET | DBG_LOG, p) {
        if (likely(dpi_is_ipv4(p))) {
            struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
            DEBUG_LOG_NO_FILTER("packet sip="DBG_IPV4_FORMAT" dip="DBG_IPV4_FORMAT
                  " proto %d sport %d dport %d policy %s\n",
                  DBG_IPV4_TUPLE(iph->saddr), DBG_IPV4_TUPLE(iph->daddr),
                  p->ip_proto, p->sport, p->dport,
                  (desc->action == DP_POLICY_ACTION_VIOLATE)?"violated":"denied");
        }
    }

    if (unlikely(p->session != NULL)) {
        dpi_session_log(p->session, &dps, &dpm);
    } else {
        dpi_session_log_from_pkt(p, to_server, desc, &dps);
    }

    if (likely(!FLAGS_TEST(p->flags, DPI_PKT_FLAG_FAKE_EP))) {
        g_io_callback->connect_report(&dps, p->session != NULL ? &dpm : NULL, 0, 1);
    }
    // g_io_callback->traffic_log(&dps);
}
