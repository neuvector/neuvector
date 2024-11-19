#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "utils/helper.h"

#include "dpi/dpi_module.h"

#define SESS_TIMEOUT_TCP_OPEN           20
#define SESS_TIMEOUT_TCP_ACTIVE_NODATA  30    // TODO: configurable?
#define SESS_TIMEOUT_TCP_ACTIVE         1200
#define SESS_TIMEOUT_TCP_HALF_CLOSE     90
#define SESS_TIMEOUT_TCP_CLOSE          15
#define SESS_TIMEOUT_TCP_RST            60
#define SESS_TIMEOUT_TCP_SHORT          2
#define SESS_TIMEOUT_IP   15
#define SESS_TIMEOUT_UDP  30
#define SESS_TIMEOUT_ICMP 5

#define SESS_ALLOW_MID_STREAM_WINDOW    300

#define SESS_SMALL_WINDOW_DURATION      8
#define SESS_SMALL_WINDOW_SERVER_IGNORE (16 * 1024)
#define SESS_SMALL_WINDOW_CLIENT_IGNORE (8 * 1024)
#define SESS_SMALL_WINDOW_DROP          (4 * 1024)
#define SESS_SMALL_WINDOW_SIZE          16

#define SESS_FLAGS_FOR_LOOKUP (DPI_SESS_FLAG_INGRESS | DPI_SESS_FLAG_FAKE_EP)

extern bool cmp_mac_prefix(void *m1, void *prefix);

static void dpi_session_tick_timeout(timer_entry_t *n);
static void tcp_scan_detection_release(dpi_session_t *s);

static int session4_proxymesh_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_session_t *s = STRUCT_OF(ht_node, dpi_session_t, node);
    const dpi_session_t *k = key;
    int matched = 0;

    if (s->client.ip.ip4 == k->client.ip.ip4 &&
        s->client.port == k->client.port && 
        s->ip_proto == k->ip_proto) {
        matched = 1;
        if (s->server.ip.ip4 == htonl(INADDR_LOOPBACK) && 
            s->client.ip.ip4 != htonl(INADDR_LOOPBACK)) {
            s->server.ip.ip4 = k->server.ip.ip4;
            s->server.port = k->server.port;
            //return packet from svr shows correct svr ip
            //instead of 127.0.0.1, this is for istio
            FLAGS_SET(s->flags, DPI_SESS_FLAG_MESH_TO_SVR);

            s->policy_desc.flags &= ~(POLICY_DESC_INTERNAL|POLICY_DESC_EXTERNAL);
            if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS)) {
                s->policy_desc.flags |= dpi_is_ip4_internal(s->client.ip.ip4)?
                                   POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
            } else {
                s->policy_desc.flags |= dpi_is_ip4_internal(s->server.ip.ip4)?
                                   POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
            }
        }
    }

    return matched;
}

static int session4_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_session_t *s = STRUCT_OF(ht_node, dpi_session_t, node);
    const dpi_session_t *k = key;

    return s->client.ip.ip4 == k->client.ip.ip4 && s->server.ip.ip4 == k->server.ip.ip4 &&
           s->client.port == k->client.port && s->server.port == k->server.port &&
           s->ip_proto == k->ip_proto &&
           (s->flags & SESS_FLAGS_FOR_LOOKUP) == (k->flags & SESS_FLAGS_FOR_LOOKUP);
}

static uint32_t session4_proxymesh_hash(const void *key)
{
    const dpi_session_t *k = key;
    uint32_t port = k->client.port;

    return sdbm_hash((uint8_t *)&k->client.ip, 4) +
           sdbm_hash((uint8_t *)&port, sizeof(port));
}

static uint32_t session4_hash(const void *key)
{
    const dpi_session_t *k = key;
    uint32_t port = (k->client.port << 16) + k->server.port;

    return sdbm_hash((uint8_t *)&k->client.ip, 4) +
           sdbm_hash((uint8_t *)&k->server.ip, 4) +
           sdbm_hash((uint8_t *)&port, sizeof(port));
}

static int session6_proxymesh_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_session_t *s = STRUCT_OF(ht_node, dpi_session_t, node);
    const dpi_session_t *k = key;
    int matched = 0;

    if (memcmp(&s->client.ip, &k->client.ip, sizeof(k->client.ip)) == 0 &&
        s->client.port == k->client.port && s->ip_proto == k->ip_proto) {
        matched = 1;
        if (memcmp((uint8_t *)&s->server.ip, (uint8_t *)(in6addr_loopback.s6_addr), sizeof(s->server.ip)) == 0 &&
            memcmp((uint8_t *)&s->client.ip, (uint8_t *)(in6addr_loopback.s6_addr), sizeof(s->client.ip)) != 0) {
            memcpy(&s->server.ip, &k->server.ip, sizeof(s->server.ip));
            s->server.port = k->server.port;
        }
    }

    return matched;
}

static int session6_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_session_t *s = STRUCT_OF(ht_node, dpi_session_t, node);
    const dpi_session_t *k = key;

    return memcmp(&s->client.ip, &k->client.ip, sizeof(k->client.ip)) == 0 &&
           memcmp(&s->server.ip, &k->server.ip, sizeof(k->server.ip)) == 0 &&
           s->client.port == k->client.port && s->server.port == k->server.port &&
           s->ip_proto == k->ip_proto &&
           (s->flags & SESS_FLAGS_FOR_LOOKUP) == (k->flags & SESS_FLAGS_FOR_LOOKUP);
}

static uint32_t session6_proxymesh_hash(const void *key)
{
    const dpi_session_t *k = key;
    uint32_t port = k->client.port;

    return sdbm_hash((uint8_t *)&k->client.ip, sizeof(k->client.ip)) +
           sdbm_hash((uint8_t *)&port, sizeof(port));
}

static uint32_t session6_hash(const void *key)
{
    const dpi_session_t *k = key;
    uint32_t port = (k->client.port << 16) + k->server.port;

    return sdbm_hash((uint8_t *)&k->client.ip, sizeof(k->client.ip)) +
           sdbm_hash((uint8_t *)&k->server.ip, sizeof(k->server.ip)) +
           sdbm_hash((uint8_t *)&port, sizeof(port));
}

int dpi_session_start_log(dpi_session_t *s, bool xff)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_SESSION | DBG_LOG, NULL);

    DPMsgSession dps;
    DPMonitorMetric dpm;
    if (!xff) {
        if (unlikely((s->last_report > 0))) {
            // Indicating this start log is a retry. The early failure should be due to
            // connection table full. Let's wait a little time to do the retry
            if (th_snap.tick - s->last_report < 2 ) {
                return -1;
            }
        }

        dpi_session_log(s, &dps, &dpm);
    } else {
        dpi_session_log(s, &dps, &dpm);
        //change xff related value
        if (dpi_session_log_xff(s, &dps) < 0) {
            return -1;
        }
    }

    if (likely(!FLAGS_TEST(s->flags, DPI_SESS_FLAG_FAKE_EP))) {
        int ret;
        if (!xff) {
            ret = g_io_callback->connect_report(&dps, &dpm, 1,
                     (s->policy_desc.action > DP_POLICY_ACTION_CHECK_APP)?1:0);
        } else {
            ret = g_io_callback->connect_report(&dps, &dpm, 1,
                     (s->xff_desc.action > DP_POLICY_ACTION_CHECK_APP)?1:0);
        }
        s->last_report = th_snap.tick;
        if (likely(ret > 0)) {
            s->client.reported_bytes = s->client.bytes;
            s->client.reported_pkts = s->client.pkts;
            s->server.reported_bytes = s->server.bytes;
            s->server.reported_pkts = s->server.pkts;
        } else {
            return -1;
        }
    }
    return 0;
}

static void dpi_session_end_log(dpi_session_t *s, int log_violate, bool xff)
{
    DEBUG_LOG(DBG_SESSION | DBG_LOG, NULL, "action=%u reason=%u severity=%u pkt=%u:%u\n",
              s->policy_desc.action, s->term_reason, s->severity, s->client.pkts, s->server.pkts);

    DPMsgSession dps;
    DPMonitorMetric dpm;
    dpi_session_log(s, &dps, &dpm);

    // g_io_callback->traffic_log(&dps);

    dps.ClientPkts -= s->client.reported_pkts;
    dps.ClientBytes -= s->client.reported_bytes;
    dps.ServerPkts -= s->server.reported_pkts;
    dps.ServerBytes -= s->server.reported_bytes;

    if (xff) {
        //change xff related value
        if (dpi_session_log_xff(s, &dps) < 0) {
            return;
        }
        if (likely(!FLAGS_TEST(s->flags, DPI_SESS_FLAG_FAKE_EP))) {
            // Always report if xff policy action is deny/violate; 
            if (unlikely(s->xff_desc.action > DP_POLICY_ACTION_CHECK_APP)) {
                // See if start_log has been done
                if (likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_START_LOGGED))) {
                    g_io_callback->connect_report(&dps, &dpm, 0, log_violate);
                } else {
                    g_io_callback->connect_report(&dps, &dpm, 1, 1);
                }
            }
        }
        return;
    }

    if (likely(!FLAGS_TEST(s->flags, DPI_SESS_FLAG_FAKE_EP))) {
        uint32_t s_pkts_min = 0;
        if (unlikely(s->flags & DPI_SESS_FLAG_MID_STREAM)) {
            // In case of port scan with -sA, session is marked as mid-stream. This is to prevent
            // case like "C:ACK, S:RST" to generate report
            s_pkts_min = 1;
        }

        // Always report if policy action is deny/violate; otherwise,
        // only report if the session has been established. This is to
        // avoid reporting port-scan sessions and considering them as
        // valid sessions.
        if (unlikely(s->policy_desc.action > DP_POLICY_ACTION_CHECK_APP ||
                     s->term_reason != DPI_SESS_TERM_NORMAL)) {
            // See if start_log has been done
            if (likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_START_LOGGED))) {
                g_io_callback->connect_report(&dps, &dpm, 0, log_violate);
            } else {
                g_io_callback->connect_report(&dps, &dpm, 1, 1);
            }
        } else if (likely(s->server.pkts > s_pkts_min)) {
            if (s->ip_proto != IPPROTO_TCP ||
                likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_ESTABLISHED)) ||
                unlikely(s->severity > 0)) {
                // See if start_log has been done
                if (likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_START_LOGGED))) {
                    g_io_callback->connect_report(&dps, &dpm, 0, 0);
                } else {
                    g_io_callback->connect_report(&dps, &dpm, 1, 0);
                }
            }
        } else if (unlikely(s->severity > 0)) {
            // See if start_log has been done
            if (likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_START_LOGGED))) {
                g_io_callback->connect_report(&dps, &dpm, 0, 0);
            } else {
                g_io_callback->connect_report(&dps, &dpm, 1, 0);
            }
        }
    }
}

// No traffic log, only report connect
void dpi_session_mid_log(dpi_session_t *s, int log_violate, bool xff)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_SESSION | DBG_LOG, NULL);

    DPMsgSession dps;
    DPMonitorMetric dpm;
    dpi_session_log(s, &dps, &dpm);

    if (xff) {
        //change xff related value
        if (dpi_session_log_xff(s, &dps) < 0) {
            return;
        }
    }

    dps.ClientPkts -= s->client.reported_pkts;
    dps.ClientBytes -= s->client.reported_bytes;
    dps.ServerPkts -= s->server.reported_pkts;
    dps.ServerBytes -= s->server.reported_bytes;

    if (likely(!FLAGS_TEST(s->flags, DPI_SESS_FLAG_FAKE_EP))) {
        int ret = g_io_callback->connect_report(&dps, &dpm, 0, log_violate);
        if (likely(ret > 0)) {
            s->client.reported_bytes = s->client.bytes;
            s->client.reported_pkts = s->client.pkts;
            s->server.reported_bytes = s->server.bytes;
            s->server.reported_pkts = s->server.pkts;
        }
    }
    // Mark last report regardless of actual report to avoid the
    // function being called too frequently
    s->last_report = th_snap.tick;
}

void dpi_asm_remove(clip_t *clip)
{
    th_counter.freed_asms ++;
    free(clip);
}

int dpi_cache_packet(dpi_packet_t *p, dpi_wing_t *w, bool lookup)
{
    clip_t *clip;

    if (lookup && (asm_lookup(&w->asm_cache, p->raw.seq) != NULL)) {
        return -1;
    }

    clip = malloc(sizeof(*clip) + p->raw.len);
    if (clip == NULL) {
        return -1;
    }

    th_counter.total_asms ++;
    clip->seq = p->raw.seq;
    clip->skip = 0;
    clip->len = p->raw.len;
    clip->ptr = (uint8_t *)(clip + 1);
    memcpy(clip->ptr, p->raw.ptr, p->raw.len);

    if (asm_insert(&w->asm_cache, clip) == ASM_FAILURE) {
        // DEBUG_ERROR(DBG_TCP, "Fail to cache because packet duplication\n");
        dpi_asm_remove(clip);
        return -1;
    } else {
        DEBUG_LOG(DBG_TCP, p, "Cache packet, len=%u\n", p->raw.len);
        p->flags |= DPI_PKT_FLAG_CACHED;
    }

    return 0;
}

// timer

// Session must be on the timer wheel to call this function
static inline void dpi_session_timer_reprogram(dpi_session_t *s, timer_wheel_expire_fct cb, uint16_t timeout)
{
    timer_wheel_entry_set_callback(&s->ts_entry, cb);
    timer_wheel_entry_set_timeout(&s->ts_entry, timeout);
    timer_wheel_entry_refresh(&th_timer, &s->ts_entry, th_snap.tick);
}

// Session must be on the timer wheel to call this function
static inline void dpi_session_timer_refresh(dpi_session_t *s)
{
    timer_wheel_entry_refresh(&th_timer, &s->ts_entry, th_snap.tick);
}

// Session must NOT be on the timer wheel to call this function
static inline void dpi_session_timer_start(dpi_session_t *s, timer_wheel_expire_fct cb, uint16_t timeout)
{
    timer_wheel_entry_start(&th_timer, &s->ts_entry, cb, timeout, th_snap.tick);
}

static inline void dpi_session_timer_remove(dpi_session_t *s)
{
    timer_wheel_entry_remove(&th_timer, &s->ts_entry);
}

void dpi_session_start_tick_for(dpi_session_t *s, uint8_t flag, dpi_packet_t *p)
{
    if (likely(s->tick_flags == 0)) {
        DEBUG_LOG(DBG_SESSION, p, "Start session tick\n");

        dpi_session_set_tick(s, flag);
        timer_wheel_entry_start(&th_timer, &s->tick_entry,
                                dpi_session_tick_timeout, SESS_TIMEOUT_TCP_SHORT, th_snap.tick);
    } else {
        dpi_session_set_tick(s, flag);
    }
}

static inline void dpi_session_resume_tick(dpi_session_t *s)
{
    timer_wheel_entry_start(&th_timer, &s->tick_entry,
                            dpi_session_tick_timeout, SESS_TIMEOUT_TCP_SHORT, th_snap.tick);
}

void dpi_session_stop_tick_for(dpi_session_t *s, uint8_t flag, dpi_packet_t *p)
{
    dpi_session_unset_tick(s, flag);
    if (likely(s->tick_flags == 0)) {
        DEBUG_LOG(DBG_SESSION, p, "Stop session tick\n");

        timer_wheel_entry_remove(&th_timer, &s->tick_entry);
    }
}

bool dpi_session_is_tick_running(dpi_session_t *s)
{
    return timer_wheel_entry_is_active(&s->tick_entry);
}

dpi_session_t *dpi_session_lookup(dpi_packet_t *p)
{
    dpi_session_t *s, key;
    bool ingress = !!(p->flags & DPI_PKT_FLAG_INGRESS);
    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);
    
    DEBUG_LOG_FUNC_ENTRY(DBG_PACKET, p);

    memset(&key.client.ip, 0, sizeof(key.client.ip));
    memset(&key.server.ip, 0, sizeof(key.server.ip));

    key.ip_proto = p->ip_proto;

    // Try client side
    if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_FAKE_EP))) {
        // For pcap pcacket, session is always marked as INGRESS
        key.flags = DPI_SESS_FLAG_INGRESS | DPI_SESS_FLAG_FAKE_EP;
    } else {
        key.flags = ingress ? DPI_SESS_FLAG_INGRESS : 0;
    }
    key.client.port = p->sport;
    key.server.port = p->dport;

    if (likely(p->eth_type == ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        key.client.ip.ip4 = iph->saddr;
        key.server.ip.ip4 = iph->daddr;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session4_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session4_map, &key);
        }
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
        key.client.ip.ip6 = ip6h->ip6_src;
        key.server.ip.ip6 = ip6h->ip6_dst;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session6_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session6_map, &key);
        }
    }

    if (s != NULL) {
        DEBUG_LOG(DBG_PACKET, p, "Located session=%u\n", s->id);
        dpi_set_client_pkt(p);
        p->this_wing = &s->client;
        p->that_wing = &s->server;
        return s;
    }

    // Try server side
    if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_FAKE_EP))) {
        // For pcap pcacket, session is always marked as INGRESS
        key.flags = DPI_SESS_FLAG_INGRESS | DPI_SESS_FLAG_FAKE_EP;
    } else {
        key.flags = !ingress ? DPI_SESS_FLAG_INGRESS : 0;
    }
    key.client.port = p->dport;
    key.server.port = p->sport;

    if (likely(p->eth_type == ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        key.client.ip.ip4 = iph->daddr;
        key.server.ip.ip4 = iph->saddr;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session4_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session4_map, &key);
        }
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
        key.client.ip.ip6 = ip6h->ip6_dst;
        key.server.ip.ip6 = ip6h->ip6_src;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session6_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session6_map, &key);
        }
    }

    if (s != NULL) {
        DEBUG_LOG(DBG_PACKET, p, "Located session=%u\n", s->id);
        p->this_wing = &s->server;
        p->that_wing = &s->client;
        return s;
    }

    return NULL;
}

void dpi_session_release(dpi_session_t *s)
{
    DEBUG_LOG(DBG_SESSION, NULL, "id=%u asm:%u/%u\n",
              s->id, asm_gross(&s->client.asm_cache), asm_gross(&s->server.asm_cache));
    uint8_t *ep_mac = (s->flags & DPI_SESS_FLAG_INGRESS)?s->server.mac:s->client.mac;
    bool isproxymesh = cmp_mac_prefix(ep_mac, PROXYMESH_MAC_PREFIX);

    if (unlikely(dpi_session_is_tick_running(s))) {
        timer_wheel_entry_remove(&th_timer, &s->tick_entry);
    }

    dpi_meter_session_dec(s);
    dpi_dec_stats_session(s);

    if (s->ip_proto == IPPROTO_TCP) {
        tcp_scan_detection_release(s);
    }

    if (likely(s->term_reason != DPI_SESS_TERM_VOLUME)) {
/*
        int log_violate = 0;
        if (s->term_reason == DPI_SESS_TERM_POLICY) {
            log_violate = 1;
        } else {
            log_violate = dpi_sess_policy_reeval(s);
        }
        dpi_session_end_log(s, log_violate);
*/
        // 11/18/2016: We changed behavior so that session will not be
        // terminated by policy, and not to reeval at session close
        // (i.e. action is decided by last packet hitting this session).
        // Thus, log_violate parameter to the end log will be fixed to 0
        dpi_session_end_log(s, 0, false);
        if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_XFF)) {
            dpi_session_end_log(s, 0, true);
        }
    }

    asm_destroy(&s->client.asm_cache, dpi_asm_remove);
    asm_destroy(&s->server.asm_cache, dpi_asm_remove);

    dpi_purge_parser_data(s);

    if (likely(s->flags & DPI_SESS_FLAG_IPV4)) {
        if (isproxymesh) {
            rcu_map_del(&th_session4_proxymesh_map, s);
        } else {
            rcu_map_del(&th_session4_map, s);
        }
    } else {
        if (isproxymesh) {
            rcu_map_del(&th_session6_proxymesh_map, s);
        } else {
            rcu_map_del(&th_session6_map, s);
        }
    }

    th_counter.cur_sess --;
    switch (s->ip_proto) {
    case IPPROTO_TCP:    th_counter.cur_tcp_sess --; break;
    case IPPROTO_UDP:    th_counter.cur_udp_sess --; break;
    case IPPROTO_ICMP:   th_counter.cur_icmp_sess --; break;
    case IPPROTO_ICMPV6: th_counter.cur_icmp_sess --; break;
    default:             th_counter.cur_ip_sess --; break;
    }
    if ((s->flags & DPI_SESS_FLAG_FINAL_PARSER)) {
        th_counter.parser_sess[s->only_parser] ++;
        th_counter.parser_pkts[s->only_parser] += s->client.pkts + s->server.pkts;
    }

    free(s);
}

void dpi_session_timeout(timer_entry_t *n)
{
    dpi_session_t *s = STRUCT_OF(n, dpi_session_t, ts_entry);
    dpi_session_release(s);
}

void dpi_session_term_reason(dpi_session_t *s, int term)
{
    s->term_reason = term;
}

static void dpi_session_reset(dpi_session_t *s, uint32_t idx)
{
    uint8_t action = dpi_threat_action(idx);
    if (action == DPI_ACTION_ALLOW) return;

    dpi_inject_reset_by_session(s, true);
    dpi_session_term_reason(s, DPI_SESS_TERM_THREAT);

    s->action = DPI_ACTION_BLOCK;
}

static void dpi_session_tick_timeout(timer_entry_t *n)
{
    dpi_session_t *s = STRUCT_OF(n, dpi_session_t, tick_entry);

    DEBUG_LOG_FUNC_ENTRY(DBG_SESSION | DBG_TIMER, NULL);

    if (unlikely(s->small_window_tick > 0)) {
        if (th_snap.tick - s->small_window_tick >= SESS_SMALL_WINDOW_DURATION) {
            DEBUG_LOG(DBG_SESSION, NULL,
                      "TCP small-window duration=%us, threshold=%us\n",
                      th_snap.tick - s->small_window_tick, SESS_SMALL_WINDOW_DURATION);
            dpi_threat_log_by_session(DPI_THRT_TCP_SMALL_WINDOW, s,
                      "TCP small-window duration=%us, threshold=%us",
                      th_snap.tick - s->small_window_tick, SESS_SMALL_WINDOW_DURATION);

            dpi_session_unset_tick(s, DPI_SESS_TICK_FLAG_SMALL_WINDOWS);
            s->small_window_tick = 0;

            if (!FLAGS_TEST(s->flags, DPI_SESS_FLAG_TAP)) {
                dpi_session_reset(s, DPI_THRT_TCP_SMALL_WINDOW);
                dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_RST);
            }
            return;
        }
    }

    if (dpi_session_check_tick(s, DPI_SESS_TICK_FLAG_SLOWLORIS)) {
        int ret = dpi_http_tick_timeout(s, s->parser_data[DPI_PARSER_HTTP]);
        switch (ret) {
        case DPI_SESS_TICK_RESET:
            dpi_session_unset_tick(s, DPI_SESS_TICK_FLAG_SLOWLORIS);

            if (!FLAGS_TEST(s->flags, DPI_SESS_FLAG_TAP)) {
                dpi_session_reset(s, DPI_THRT_HTTP_SLOWLORIS);
                dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_RST);
            }
            return;
        case DPI_SESS_TICK_STOP:
            dpi_session_unset_tick(s, DPI_SESS_TICK_FLAG_SLOWLORIS);
            break;
        }
    }

    if (s->tick_flags != 0) {
        dpi_session_resume_tick(s);
    }
}

// This is a very simple protection schema, to reset the session if no data sent from client
// for a short period of time. Possible improvements include,
// 1. Set a shorter timeout after TWH done, count how many concurrent sessions reach and stay
//    in this state, start resetting sessions if threashold is reached;
// 2. Instead of counting total sessions, count how fast sessions reach the shorter timeout.
//
// For simplicity now, logic #2 is used.
static void session_nodata_timeout(timer_entry_t *n)
{
    dpi_session_t *s = STRUCT_OF(n, dpi_session_t, ts_entry);

    if (dpi_threat_status(DPI_THRT_TCP_NODATA)) {
        if (dpi_meter_session_rate(DPI_METER_TCP_NODATA, s)) {
            DEBUG_LOG(DBG_SESSION, NULL, "Trigger TCP nodata\n");
            dpi_threat_log_by_session(DPI_THRT_TCP_NODATA, s,
                                      "Client send no data after open connection for %us",
                                      SESS_TIMEOUT_TCP_ACTIVE_NODATA);
            if (!FLAGS_TEST(s->flags, DPI_SESS_FLAG_TAP)) {
                dpi_session_reset(s, DPI_THRT_TCP_NODATA);
                dpi_session_timer_start(s, dpi_session_timeout, SESS_TIMEOUT_TCP_RST);
            } else {
                dpi_session_timer_start(s, dpi_session_timeout, SESS_TIMEOUT_TCP_ACTIVE);
            }
        } else {
            DEBUG_LOG(DBG_SESSION, NULL, "Ignore TCP nodata\n");
            dpi_session_timer_start(s, dpi_session_timeout, SESS_TIMEOUT_TCP_ACTIVE);
        }
    } else {
        DEBUG_LOG(DBG_SESSION, NULL, "Ignore TCP nodata\n");
        dpi_session_timer_start(s, dpi_session_timeout, SESS_TIMEOUT_TCP_ACTIVE);
    }
}

/*

This is commented out because,
1. controller does this if application is not identified by data path
2. applicaiton in client and server side session are different 

void assign_session_app_by_port(dpi_packet_t *p, dpi_session_t *s)
{
    uint16_t app = dpi_ep_get_app(p);
    if (app == 0) return;

    DEBUG_LOG(DBG_SESSION, p, "app=%d\n", app);

    if (dpi_is_base_app(app)) {
        s->base_app = app;
    } else {
        s->app = app;
    }
}
*/
static void dpi_fill_proxymesh_policy_desc(dpi_packet_t *p, bool to_server, dpi_policy_desc_t *desc)
{
    struct iphdr *iph;
    uint32_t sip, dip;
    int is_ingress;
    
    memset(desc, 0, sizeof(dpi_policy_desc_t));
    /* only support ipv4 */
    switch (p->eth_type) {
    case ETH_P_IP:
        break;
    default:
        return;
    }
    
    iph = (struct iphdr *)(p->pkt + p->l3);
    sip = to_server?iph->saddr:iph->daddr;
    dip = to_server?iph->daddr:iph->saddr;
    is_ingress = to_server?p->flags & DPI_PKT_FLAG_INGRESS:!(p->flags & DPI_PKT_FLAG_INGRESS);
    DEBUG_POLICY("sip %x dip %x ingress %d\n",sip, dip, is_ingress);

    desc->id = 0;
    desc->action = DP_POLICY_ACTION_OPEN;
    //desc->flags = POLICY_DESC_CHECK_VER;
    desc->flags = 0;

    if (is_ingress) {
        desc->flags |= dpi_is_ip4_internal(sip)?
                           POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
    } else {
        desc->flags |= dpi_is_ip4_internal(dip)?
                           POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
    }
}


static dpi_session_t *dpi_session_create(dpi_packet_t *p, bool to_server)
{
    dpi_wing_t *w0, *w1;
    uint16_t timeout;
    dpi_policy_desc_t policy_desc;
    dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)p->ep->policy_hdl;
    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);

    DEBUG_LOG_FUNC_ENTRY(DBG_SESSION, p);

    if (!isproxymesh) {
        dpi_policy_lookup(p, hdl, 0, to_server, false, &policy_desc, 0);
        // Violate log if needed will be reported in start log
        // except for the drop case, so we log it here
        if (policy_desc.action == DP_POLICY_ACTION_DENY) {
            dpi_policy_violate_log(p, to_server, &policy_desc);
            dpi_set_action(p, DPI_ACTION_DROP);
            return NULL;
        }
    } else {
        //no policy match for proxymesh 'lo' i/f's session
        dpi_fill_proxymesh_policy_desc(p,to_server,&policy_desc);
    }

    dpi_session_t *s = calloc(1, sizeof(*s));
    if (unlikely(s == NULL)) {
        return NULL;
    }

    memcpy(&s->policy_desc, &policy_desc, sizeof(dpi_policy_desc_t));

    th_counter.cur_sess ++;
    switch (p->ip_proto) {
    case IPPROTO_TCP:
        th_counter.tcp_sess ++;
        th_counter.cur_tcp_sess ++;
        timeout = SESS_TIMEOUT_TCP_OPEN;
        break;
    case IPPROTO_UDP:
        th_counter.udp_sess ++;
        th_counter.cur_udp_sess ++;
        timeout = SESS_TIMEOUT_UDP;
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        th_counter.icmp_sess ++;
        th_counter.cur_icmp_sess ++;
        timeout = SESS_TIMEOUT_ICMP;
        break;
    default:
        th_counter.ip_sess ++;
        th_counter.cur_ip_sess ++;
        timeout = SESS_TIMEOUT_IP;
        break;
    }

    th_counter.sess_id ++;
    s->id = th_counter.sess_id;
    s->created_at = th_snap.tick;

    uint8_t *ep_mac = p->ep_mac;
    struct ethhdr *eth = (struct ethhdr *)(p->pkt + p->l2);
    if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_FAKE_EP))) {
        FLAGS_SET(s->flags, (DPI_SESS_FLAG_INGRESS | DPI_SESS_FLAG_FAKE_EP));
        mac_cpy(s->client.mac, eth->h_source);
        mac_cpy(s->server.mac, eth->h_dest);
    } else if (p->flags & DPI_PKT_FLAG_INGRESS) {
        if (likely(to_server)) {
            FLAGS_SET(s->flags, DPI_SESS_FLAG_INGRESS);
            mac_cpy(s->client.mac, eth->h_source);
            mac_cpy(s->server.mac, ep_mac);
        } else {
            mac_cpy(s->client.mac, ep_mac);
            mac_cpy(s->server.mac, eth->h_source);
        }
    } else {
        if (likely(to_server)) {
            mac_cpy(s->client.mac, ep_mac);
            mac_cpy(s->server.mac, eth->h_dest);
        } else {
            FLAGS_SET(s->flags, DPI_SESS_FLAG_INGRESS);
            mac_cpy(s->client.mac, eth->h_dest);
            mac_cpy(s->server.mac, ep_mac);
        }
    }

    if (p->ep->tap) {
        FLAGS_SET(s->flags, DPI_SESS_FLAG_TAP);
    }

    s->ip_proto = p->ip_proto;

    if (likely(to_server)) {
        dpi_set_client_pkt(p);
        w0 = p->this_wing = &s->client;
        w1 = p->that_wing = &s->server;
    } else {
        w0 = p->this_wing = &s->server;
        w1 = p->that_wing = &s->client;
    }

    w0->port = p->sport;
    w1->port = p->dport;
    if (likely(p->eth_type == ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        w0->ip.ip4 = iph->saddr;
        w1->ip.ip4 = iph->daddr;
        s->flags |= DPI_SESS_FLAG_IPV4;
        if (isproxymesh) {
            rcu_map_add(&th_session4_proxymesh_map, s, s);
        } else {
            rcu_map_add(&th_session4_map, s, s);
        }
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
        w0->ip.ip6 = ip6h->ip6_src;
        w1->ip.ip6 = ip6h->ip6_dst;
        if (isproxymesh) {
            rcu_map_add(&th_session6_proxymesh_map, s, s);
        } else {
            rcu_map_add(&th_session6_map, s, s);
        }
    }

    asm_init(&s->client.asm_cache);
    asm_init(&s->server.asm_cache);

    FLAGS_SET(p->flags, DPI_PKT_FLAG_NEW_SESSION);

    timer_wheel_entry_init(&s->ts_entry);
    timer_wheel_entry_init(&s->tick_entry);
    dpi_session_timer_start(s, dpi_session_timeout, timeout);
    s->last_report = 0;

    p->this_wing->pkts ++;
    p->this_wing->bytes += p->cap_len;

    dpi_inc_stats_session(p, s);

    IF_DEBUG_LOG(DBG_SESSION, p) {
        DEBUG_LOG_NO_FILTER("Created session=%u ingress=%d ep_mac="DBG_MAC_FORMAT" policy="
              DP_POLICY_DESC_STR "\n",
              s->id, !!(s->flags & DPI_SESS_FLAG_INGRESS), DBG_MAC_TUPLE(*ep_mac),
              DP_POLICY_DESC((&s->policy_desc)));
        debug_dump_session_short(s);
    }

    return s;
}

// Return if packet is to server
static bool tcp_mid_session_direction(dpi_packet_t *p)
{
    bool ingress = FLAGS_TEST(p->flags, DPI_PKT_FLAG_INGRESS);
    uint16_t port = ingress ? p->dport : p->sport;

    io_app_t *app = dpi_ep_app_map_lookup(p->ep, port, p->ip_proto);
    if (app != NULL) {
        // workload is the server
        return ingress ? true : false;
    } else {
        // if opened port on EP cannot be found, the workload could be client, but
        // it also could be because we have not scanned the opened port. =>
        // Treat smaller port as server
        return p->dport < p->sport;

        // workload is the client
        // return ingress ? false : true;
    }
}

static bool udp_mid_session_direction(dpi_packet_t *p)
{
    bool ingress = FLAGS_TEST(p->flags, DPI_PKT_FLAG_INGRESS);
    uint16_t port = ingress ? p->dport : p->sport;

    io_app_t *app = dpi_ep_app_map_lookup(p->ep, port, p->ip_proto);
    if (app != NULL) {
        // workload is the server
        return ingress ? true : false;
    } else {
        // A bit of hack here, compared to the TCP version, UDP source port can be
        // as small as 1024

        // workload is the client
        return ingress ? false : true;
    }
}

void dpi_udp_tracker(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;

    if (unlikely(s == NULL)) {
        bool to_server;

        // DHCP server port is 67, client is 68
#define DHCP_SERVER_PORT 67
#define DNS_SERVER_PORT  53
#define DNS_MC_SERVER_PORT  5353
        if (unlikely(p->dport == DHCP_SERVER_PORT || p->dport == DNS_SERVER_PORT || p->dport == DNS_MC_SERVER_PORT)) {
            to_server = true;
        } else if (unlikely(p->sport == DHCP_SERVER_PORT || p->sport == DNS_SERVER_PORT || p->sport == DNS_MC_SERVER_PORT)) {
            to_server = false;
        } else {
            // In offline mode, when load is heavy, not all packets can be put in the queue,
            // we could mis-identify session direction for UDP => perform the direction check
            // based on opened ports of the workload.
            to_server = udp_mid_session_direction(p);
        }
        s = dpi_session_create(p, to_server);
        if (unlikely(s == NULL)) {
            DEBUG_ERROR(DBG_SESSION, "Unable to create UDP session\n");
            return;
        }

        if (unlikely(dpi_meter_session_inc(p, s) != DPI_METER_ACTION_NONE)) {
            dpi_session_delete(s, DPI_SESS_TERM_VOLUME);
            dpi_set_action(p, DPI_ACTION_DROP);
            return;
        }

        DEBUG_LOG(DBG_SESSION, p, "Created UDP session\n");

        p->session = s;
        // assign_session_app_by_port(p, s);
    } else {
        dpi_session_timer_refresh(s);
    }

    p->raw.seq = p->this_wing->next_seq;
    p->this_wing->next_seq = p->raw.seq + p->raw.len;
}


#define ICMP_TUNNEL_THRESHOD  3
#define ICMP_TUNNEL_REPORTED  255
void dpi_icmp_tunneling_check(dpi_packet_t *p)
{
    uint32_t len = dpi_pkt_len(p);
    uint8_t *ptr = dpi_pkt_ptr(p);
    dpi_wing_t *client = &p->session->client;
    struct icmphdr *icmph = (struct icmphdr *)(p->pkt + p->l4);

    if (client->icmp_times == ICMP_TUNNEL_REPORTED) {
        return;
    }

    if (icmph->type == ICMP_ECHO) {
        uint32_t hash = sdbm_hash(ptr, len);

        client->icmp_echo_hash = hash;
        client->icmp_echo_seq = icmph->un.echo.sequence;
    } else if (icmph->type == ICMP_ECHOREPLY) {
        uint32_t hash = sdbm_hash(ptr, len);

        if (client->icmp_echo_seq == icmph->un.echo.sequence && client->icmp_echo_hash != 0) {
            if (client->icmp_echo_hash == hash) {
                client->icmp_times = 0;
            } else {
                client->icmp_times ++;
                if (client->icmp_times == ICMP_TUNNEL_THRESHOD) {
                    client->icmp_times = ICMP_TUNNEL_REPORTED;
                    dpi_threat_trigger(DPI_THRT_ICMP_TUNNELING, p, "ICMP tunneling");
                }
            }
            client->icmp_echo_hash = 0;
            client->icmp_echo_seq = 0;
        }
    }
}

extern int dpi_parse_embed_icmpv6(dpi_packet_t *p);
extern int dpi_parse_embed_icmp(dpi_packet_t *p);
void dpi_icmp_tracker(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    dpi_meter_action_t act;

    if (p->ip_proto == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(p->pkt + p->l4);
        if (icmph->type == ICMP_DEST_UNREACH) {
            if (dpi_parse_embed_icmp(p) < 0){
                dpi_set_action(p,DPI_ACTION_DROP);
            } else {
                dpi_set_action(p,DPI_ACTION_BYPASS);
            }
            return;
        }
    } else {
        struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)(p->pkt + p->l4);
        if (icmp6h->icmp6_type == ICMP6_DST_UNREACH) {
            if (dpi_parse_embed_icmpv6(p) < 0) {
                dpi_set_action(p,DPI_ACTION_DROP);
            } else {
                dpi_set_action(p,DPI_ACTION_BYPASS);
            }
            return;
        }
    }

    if (dpi_threat_status(DPI_THRT_ICMP_FLOOD) && dpi_is_client_pkt(p)) {
        act = dpi_meter_packet_inc(DPI_METER_ICMP_FLOOD, p);
        if (unlikely(act != DPI_METER_ACTION_NONE)) {
            return;
        }
    }

    if (unlikely(s == NULL)) {
        s = dpi_session_create(p, dpi_is_client_pkt(p));
        if (unlikely(s == NULL)) {
            DEBUG_ERROR(DBG_SESSION, "Unable to create ICMP session\n");
            return;
        }

        if (unlikely(dpi_meter_session_inc(p, s) != DPI_METER_ACTION_NONE)) {
            dpi_session_delete(s, DPI_SESS_TERM_VOLUME);
            dpi_set_action(p, DPI_ACTION_DROP);
            return;
        }

        DEBUG_LOG(DBG_SESSION, p, "Created ICMP session\n");

        p->session = s;
        s->client.icmp_echo_hash = 0;
        s->client.icmp_echo_seq = 0;
        s->client.icmp_times = 0; 
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SKIP_PARSER);
        if (g_enable_icmp_policy) {
            FLAGS_SET(s->flags, DPI_SESS_FLAG_POLICY_APP_READY);
        }
    } else {
        dpi_session_timer_refresh(s);
    }

#define PING_DEATH_LENGTH 32000
    if (p->raw.len > PING_DEATH_LENGTH && dpi_is_client_pkt(p)) {
        DEBUG_LEVEL(DBG_PACKET, "Large packet length %u\n", p->raw.len);
        dpi_threat_trigger(DPI_THRT_PING_DEATH, p, "Large ICMP packet payload of size %u (>%u)", p->raw.len, PING_DEATH_LENGTH);
    }

    dpi_icmp_tunneling_check(p);

    p->raw.seq = p->this_wing->next_seq;
    p->this_wing->next_seq = p->raw.seq + p->raw.len;
}

void dpi_ip_tracker(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;

    if (unlikely(s == NULL)) {
        s = dpi_session_create(p, true);
        if (unlikely(s == NULL)) {
            DEBUG_ERROR(DBG_SESSION, "Unable to create IP session\n");
            return;
        }

        if (unlikely(dpi_meter_session_inc(p, s) != DPI_METER_ACTION_NONE)) {
            dpi_session_delete(s, DPI_SESS_TERM_VOLUME);
            dpi_set_action(p, DPI_ACTION_DROP);
            return;
        }

        DEBUG_LOG(DBG_SESSION, p, "Created IP session\n");

        p->session = s;
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SKIP_PARSER);
    } else {
        dpi_session_timer_refresh(s);
    }

    p->raw.seq = p->this_wing->next_seq;
    p->this_wing->next_seq = p->raw.seq + p->raw.len;
}

static char *tcp_state_name[] = {
[TCP_ESTABLISHED] = "ESTABLISHED",
[TCP_SYN_SENT] = "SYN_SENT",
[TCP_SYN_RECV] = "SYN_RECV",
[TCP_FIN_WAIT1] = "FIN_WAIT1",
[TCP_FIN_WAIT2] = "FIN_WAIT2",
[TCP_TIME_WAIT] = "TIME_WAIT",
[TCP_CLOSE] = "CLOSE",
[TCP_CLOSE_WAIT] = "CLOSE_WAIT",
[TCP_LAST_ACK] = "LAST_ACK",
[TCP_LISTEN] = "LISTEN",
[TCP_CLOSING] = "CLOSING",
};

const char *dpi_get_tcp_state_name(int state)
{
    return tcp_state_name[state];
}

static void tcp_open_by_syn(dpi_session_t *s)
{
    s->client.tcp_state = TCP_SYN_SENT;
    s->server.tcp_state = TCP_LISTEN;
}

static void tcp_open_by_synack(dpi_session_t *s)
{
    s->client.tcp_state = TCP_SYN_SENT;
    s->server.tcp_state = TCP_SYN_RECV;
}

static void tcp_open_by_mid_stream(dpi_session_t *s, dpi_packet_t *p)
{
    s->client.tcp_state = TCP_ESTABLISHED;
    s->server.tcp_state = TCP_ESTABLISHED;
    {
        struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
        uint32_t seq = p->raw.seq, ack = ntohl(tcph->th_ack);
        p->this_wing->init_seq = p->this_wing->next_seq = p->this_wing->asm_seq = seq;
        p->that_wing->init_seq = p->that_wing->next_seq = p->that_wing->asm_seq = p->that_wing->tcp_acked = ack;
    }
    dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_ACTIVE);
    FLAGS_SET(s->flags, DPI_SESS_FLAG_MID_STREAM |
                        DPI_SESS_FLAG_ESTABLISHED);
}


static int tcp_is_in_window(dpi_packet_t *p)
{
    dpi_wing_t *w0 = p->this_wing, *w1 = p->that_wing;
    uint32_t win = w1->tcp_win;
    uint32_t seq = p->raw.seq;

    if (w0->tcp_acked == 0 ||
        // allow resent acked packet within the range of 64K
        u32_between(seq, w0->tcp_acked - 65536, w0->tcp_acked + win + 1)) {
        return true;
    }

    // It could be injected packets, but most likely the ACK of the other side was lost.
    DEBUG_LOG(DBG_TCP, p, "TCP out of window, seq=0x%x acked=0x%x win=%u, offset: seq=%u acked=%u\n",
                          seq, w0->tcp_acked, win,
                          u32_distance(w0->init_seq, seq),
                          u32_distance(w0->init_seq, w0->tcp_acked));

    return false;
}

#define TCP_EVT_NORMAL 0
#define TCP_EVT_SYN    1
#define TCP_EVT_SYNACK 2
#define TCP_EVT_TWH    3
#define TCP_EVT_SPLIT  4
#define TCP_EVT_FIN    5
#define TCP_EVT_RST    6

static char *tcp_event_name[] = {
[TCP_EVT_NORMAL] = "ACK",
[TCP_EVT_SYN] = "SYN",
[TCP_EVT_SYNACK] = "SYNACK",
[TCP_EVT_TWH] = "HANDSHAKE",
[TCP_EVT_SPLIT] = "SPLIT",
[TCP_EVT_FIN] = "FIN",
[TCP_EVT_RST] = "RESET",
};

const char *get_tcp_event_name(int evt)
{
    return tcp_event_name[evt];
}

static void tcp_scan_detection_reset(dpi_packet_t *p, dpi_session_t *s)
{
    if (!dpi_is_client_pkt(p) &&
        s->client.tcp_state == TCP_SYN_SENT && s->server.tcp_state == TCP_SYN_RECV) {
        // SYN -> RST, not necessarily a scan, could be mis-config
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SCAN);
    } else if (dpi_is_client_pkt(p) &&
        s->client.tcp_state == TCP_ESTABLISHED && s->server.tcp_state == TCP_SYN_RECV) {
        // SYN -> SYN/ACK -> RST
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SCAN);
    } else if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_MID_STREAM) && p->this_wing->pkts == 1) {
        // RST is the first packet of the wing. This could be ACK scan.
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SCAN);
    }
}

static void tcp_scan_detection_release(dpi_session_t *s)
{
    if (s->client.tcp_state == TCP_SYN_SENT && s->server.tcp_state == TCP_SYN_RECV) {
        // SYN with no reply, not necessarily a scan, could be mis-config
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SCAN);
    } else if (s->client.tcp_state == TCP_ESTABLISHED && s->server.tcp_state == TCP_SYN_RECV) {
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SCAN);
    } else if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_MID_STREAM) && (s->client.pkts == 0 || s->server.pkts == 0)) {
        FLAGS_SET(s->flags, DPI_SESS_FLAG_SCAN);
    }
}

static int tcp_update_state(dpi_packet_t *p, dpi_session_t *s)
{
    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);

    if (unlikely(tcph->rst)) {
        tcp_scan_detection_reset(p, s);

        s->client.tcp_state = s->server.tcp_state = TCP_CLOSE;
        dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_CLOSE);
        return TCP_EVT_RST;
    }

    switch (p->that_wing->tcp_state) {
    case TCP_LISTEN:
        if (tcph->syn) {
            s->server.tcp_state = TCP_SYN_RECV;
            return TCP_EVT_SYN;
        }
        break;

    case TCP_SYN_SENT:
        if (tcph->syn && tcph->ack) {
            s->client.tcp_state = TCP_ESTABLISHED;
            return TCP_EVT_SYNACK;
        } else if (tcph->syn && !tcph->ack) {
            // 4-way handshake
            s->client.tcp_state = TCP_SYN_RECV;
            return TCP_EVT_SYNACK;
        }
        break;

    case TCP_SYN_RECV:
        if (!tcph->syn && tcph->ack && dpi_is_client_pkt(p)) {
            s->client.tcp_state = s->server.tcp_state = TCP_ESTABLISHED;
            return TCP_EVT_TWH;
        }
        if (tcph->syn && tcph->ack) {
            // Client has sent SYN now sends SYN/ACK, split handshake
            s->client.tcp_state = s->server.tcp_state = TCP_ESTABLISHED;
            return TCP_EVT_SPLIT;
        }
        break;

    case TCP_ESTABLISHED:
        if (unlikely(tcph->fin)) {
            p->this_wing->tcp_state = TCP_FIN_WAIT1;
            p->that_wing->tcp_state = TCP_CLOSE_WAIT;
            return TCP_EVT_FIN;
        } else if (unlikely(tcph->syn && !tcph->ack && s->server.tcp_state == TCP_SYN_RECV)) {
            // server has sent SYN/ACK now sends SYN again, split handshake
            s->server.tcp_state = TCP_ESTABLISHED;
            return TCP_EVT_SPLIT;
        }
        break;

    case TCP_FIN_WAIT1:
        // That side state is at FIN_WAIT1 => That side has sent FIN without ACK-ed
        if (tcph->fin) {
            p->this_wing->tcp_state = TCP_LAST_ACK;
            p->that_wing->tcp_state = TCP_FIN_WAIT2;
            // Both sides send FIN
            dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_CLOSE);
            return TCP_EVT_FIN;
        } else if (!tcph->syn && tcph->ack) {
            p->this_wing->tcp_state = TCP_CLOSE_WAIT;
            p->that_wing->tcp_state = TCP_FIN_WAIT2;
            // This side ACK-s, not sending FIN yet.
            dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_HALF_CLOSE);
        }
        break;

    case TCP_FIN_WAIT2:
        // That side state is at FIN_WAIT2 => That side has sent FIN and ACK-ed
        if (tcph->fin) {
            // Both sides send FIN
            p->this_wing->tcp_state = TCP_LAST_ACK;
            p->that_wing->tcp_state = TCP_TIME_WAIT;
            dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_CLOSE);
            return TCP_EVT_FIN;
        }
        break;

    case TCP_CLOSE_WAIT:
        // That side state is at CLOSE_WAIT => This side has sent FIN without ACK-ed
        /* No state change, until the other side ACK-s.
        if (tcph->fin) {
            p->this_wing->tcp_state = TCP_FIN_WAIT2;
            p->that_wing->tcp_state = TCP_LAST_ACK;
            return TCP_EVT_FIN;
        } else if (!tcph->syn && tcph->ack) {
            p->this_wing->tcp_state = TCP_FIN_WAIT2;
        }
        */
        break;

    case TCP_LAST_ACK:
        // That side state is at LAST_ACK => Both sides have sent FIN
        if (!tcph->syn && tcph->ack) {
            p->that_wing->tcp_state = TCP_CLOSE;
            dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_CLOSE);
        }
        break;
    }

    return TCP_EVT_NORMAL;
}

static void tcp_update_wing(dpi_packet_t *p, dpi_session_t *s, int evt)
{
    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
    uint32_t seq = p->raw.seq, ack = ntohl(tcph->th_ack);

    switch (evt) {
    case TCP_EVT_SYN:
        s->client.init_seq = s->client.next_seq = s->client.asm_seq = seq + 1;

        s->client.tcp_wscale = min(TCP_MAX_WINSHIFT, p->tcp_wscale);
        s->client.tcp_win <<= s->client.tcp_wscale;
        s->client.tcp_mss = p->tcp_mss;
        if (p->flags & DPI_PKT_FLAG_SACKOK) {
            s->client.flags |= DPI_WING_FLAG_SACK;
        }
        break;

    case TCP_EVT_SYNACK:
        s->server.init_seq = s->server.next_seq = s->server.asm_seq = seq + 1;
        if (tcph->ack) {
            s->client.init_seq = s->client.next_seq = s->client.tcp_acked = ack;
        }

        s->server.tcp_wscale = min(TCP_MAX_WINSHIFT, p->tcp_wscale);
        s->server.tcp_win <<= s->server.tcp_wscale;
        s->server.tcp_mss = p->tcp_mss;
        if (p->flags & DPI_PKT_FLAG_SACKOK) {
            s->server.flags |= DPI_WING_FLAG_SACK;
        }
        break;

    case TCP_EVT_TWH:
        s->server.tcp_acked = ack;
        FLAGS_SET(s->flags, DPI_SESS_FLAG_ESTABLISHED);

        dpi_session_timer_reprogram(s, session_nodata_timeout, SESS_TIMEOUT_TCP_ACTIVE_NODATA);
        break;

    case TCP_EVT_FIN:
        p->this_wing->flags |= DPI_WING_FLAG_FIN;
        break;

    case TCP_EVT_RST:
        break;

    case TCP_EVT_SPLIT:
        DEBUG_ERROR(DBG_SESSION | DBG_TCP, "TCP split handshake\n");
        dpi_threat_trigger(DPI_THRT_TCP_SPLIT_HDSHK, p, NULL);
        // fall through

    case TCP_EVT_NORMAL:
        if (tcph->ack) {
            p->that_wing->tcp_acked = ack;
        }
        if (unlikely(dpi_wing_length(&s->client) == 0) && dpi_is_client_pkt(p) && p->raw.len > 0) {
            dpi_session_timer_reprogram(s, dpi_session_timeout, SESS_TIMEOUT_TCP_ACTIVE);
        }
        break;
    }
}

static void tcp_assembly(dpi_packet_t *p, dpi_session_t *s)
{
    uint32_t seq = p->raw.seq, end = seq + p->raw.len;
    dpi_wing_t *w0 = p->this_wing;

    if (p->raw.len == 0 || u32_lte(end, w0->asm_seq)) {
        // No payload or assemble line has passed the end of the packet.
        return;
    }

    if (asm_count(&w0->asm_cache) == 0 && !u32_lt(w0->asm_seq, seq)) {
        // No packet in assemble tree and the packet creates no hole.
        // Here are not sure if packet should be stored, check it after packet
        // handling is done.
        return;
    }

    if (dpi_cache_packet(p, w0, false) < 0) {
        return;
    }

    clip_t cons;
    asm_result_t ret;

    cons.seq = w0->asm_seq;
    cons.ptr = p->asm_pkt.ptr;
    cons.len = DPI_MAX_PKT_LEN - 1;

    ret = asm_construct(&w0->asm_cache, &cons, seq);
    if (ret == ASM_OK) {
        DEBUG_LOG(DBG_TCP, p, "Assemble packet, seq=0x%x len=%u\n", cons.seq, cons.len);

        p->asm_pkt.seq = cons.seq;
        p->asm_pkt.len = cons.len;

        p->flags |= DPI_PKT_FLAG_ASSEMBLED;
    } else if (ret == ASM_MORE || asm_gross(&w0->asm_cache) > DPI_MAX_PKT_LEN) {
        DEBUG_LOG(DBG_TCP, p, "Cache overrun, flush!\n");

        dpi_set_action(p, DPI_ACTION_BYPASS);
        asm_destroy(&w0->asm_cache, dpi_asm_remove);
        asm_destroy(&p->that_wing->asm_cache, dpi_asm_remove);
    }
}

static void check_small_window_attack(dpi_packet_t *p, uint32_t old_win)
{
    dpi_session_t *s = p->session;

    if (unlikely(s->small_window_tick > 0)) {
        // Already counting small-window duration
        if (likely(p->this_wing->tcp_win >= SESS_SMALL_WINDOW_SIZE)) {
            DEBUG_LOG(DBG_SESSION, p, "Exit TCP small-window detection, window=%u\n",
                                      p->this_wing->tcp_win);

            // Stop counting small-window
            s->small_window_tick = 0;
            dpi_session_stop_tick_for(s, DPI_SESS_TICK_FLAG_SMALL_WINDOWS, p);
        }
    } else if (unlikely(p->this_wing->tcp_win < SESS_SMALL_WINDOW_SIZE) &&
               old_win > p->this_wing->tcp_win &&
               // Windows size has to drop enough to trigger
               old_win - p->this_wing->tcp_win > SESS_SMALL_WINDOW_DROP &&
               // If client has transmitted some data, not to trigger small-window detection
               dpi_wing_length(&s->client) < SESS_SMALL_WINDOW_CLIENT_IGNORE &&
               // If server has transmitted some data, not to trigger small-window detection
               dpi_wing_length(&s->server) < SESS_SMALL_WINDOW_SERVER_IGNORE) {
        // Enter small-window duration
        DEBUG_LOG(DBG_SESSION, p, "Start TCP small-window detection, window=%u\n",
                                  p->this_wing->tcp_win);

        s->small_window_tick = th_snap.tick;
        dpi_session_start_tick_for(s, DPI_SESS_TICK_FLAG_SMALL_WINDOWS, p);
    }
}

static dpi_session_t *tcp_session_create(dpi_packet_t *p, bool to_server)
{
    dpi_session_t *s = dpi_session_create(p, to_server);
    if (unlikely(s == NULL)) {
        return NULL;
    }

    DEBUG_LOG(DBG_PARSER, p, "create session id=%d sport=%d dport=%d\n", s->id, p->sport, p->dport);

    if (unlikely(dpi_meter_session_inc(p, s) != DPI_METER_ACTION_NONE)) {
        dpi_session_delete(s, DPI_SESS_TERM_VOLUME);
        dpi_set_action(p, DPI_ACTION_DROP);
        return NULL;
    }

    return s;
}

void dpi_tcp_tracker(dpi_packet_t *p)
{
    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
    dpi_session_t *s = p->session;
    uint32_t seq = p->raw.seq, ack = ntohl(tcph->th_ack);
    uint32_t len = p->raw.len, end = seq + len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PACKET | DBG_TCP, p);

    if (unlikely(tcph->syn && len != 0)) {
        DEBUG_LEVEL(DBG_SESSION | DBG_TCP, "SYN with data\n");
        dpi_threat_trigger(DPI_THRT_TCP_SYN_DATA, p, NULL);
        p->session = NULL;
        return;
    }

    if (unlikely(s == NULL)) {
        if (tcph->syn) {
            if (!tcph->ack) {
                if (unlikely(dpi_meter_synflood_inc(p) != DPI_METER_ACTION_NONE)) {
                    return;
                }

                DEBUG_LOG(DBG_TCP | DBG_SESSION, p, "TCP SYN without session\n");

                s = tcp_session_create(p, true);
                if (unlikely(s == NULL)) {
                    return;
                }

                tcp_open_by_syn(s);

                p->session = s;
                // assign_session_app_by_port(p, s);
            } else {
                DEBUG_LOG(DBG_TCP | DBG_SESSION, p, "TCP SYN/ACK without session\n");

                s = tcp_session_create(p, false);
                if (unlikely(s == NULL)) {
                    return;
                }

                tcp_open_by_synack(s);

                p->session = s;
                // assign_session_app_by_port(p, s);
            }
            // session_start log is generated after 3way handshake
        } else if (tcph->rst || tcph->fin) {
            // Don't create mid-stream session for RST and FIN
            return;
        } else {
            DEBUG_LOG(DBG_TCP | DBG_SESSION, p, "Mid-stream TCP packet\n");

            // Original thought was to only allow mid-stream sessions for a short period
            // after EP added, but iptables should stop these unsolicited connections.
            /*
            if (likely(th_snap.tick - p->ep->first_session_tick >
                       SESS_ALLOW_MID_STREAM_WINDOW)) {
                DEBUG_ERROR(DBG_SESSION, "Late mid-stream packet\n");
                return;
            }
            */

            bool to_server = tcp_mid_session_direction(p);
            s = tcp_session_create(p, to_server);
            if (unlikely(s == NULL)) {
                return;
            }

            tcp_open_by_mid_stream(s, p);

            p->session = s;
            // assign_session_app_by_port(p, s);
        }

        DEBUG_LOG(DBG_SESSION, p, "Created TCP session\n");
    } else {
        if (unlikely(dpi_is_client_pkt(p) && tcph->syn && !tcph->ack)) {
            if (s->client.tcp_state == TCP_CLOSE && s->server.tcp_state == TCP_CLOSE) {
                // old session is closed, recreate
                dpi_session_timer_remove(s);
                dpi_session_release(s);
                p->session = NULL;

                if (unlikely(dpi_meter_synflood_inc(p) != DPI_METER_ACTION_NONE)) {
                    return;
                }

                s = tcp_session_create(p, true);
                if (unlikely(s == NULL)) {
                    return;
                }

                tcp_open_by_syn(s);

                DEBUG_LOG(DBG_SESSION, p, "Created TCP session\n");

                p->session = s;
                // assign_session_app_by_port(p, s);
            } else if (seq != s->client.init_seq - 1) {
                DEBUG_LEVEL(DBG_SESSION | DBG_TCP, "Invalid TCP SYN sequence, session=%u\n", s->id);
                p->session = NULL;
                return;
            }
        } else if (unlikely(!dpi_is_client_pkt(p) && tcph->syn && tcph->ack)) {
            if ((p->this_wing->tcp_state != TCP_SYN_RECV && seq != p->this_wing->init_seq - 1) ||
                ack != p->that_wing->init_seq) {
                DEBUG_LEVEL(DBG_SESSION | DBG_TCP, "Invalid TCP SYN/ACK sequence, session=%u\n", s->id);
                p->session = NULL;
                return;
            }
        }

        dpi_session_timer_refresh(s);
    }

    if (unlikely(s->flags & DPI_SESS_FLAG_MID_STREAM)) {
        // TCP state transition
        int evt = tcp_update_state(p, s);
        DEBUG_LOG(DBG_TCP, p, "event: %s => C:%s S:%s\n",
                              tcp_event_name[evt],
                              tcp_state_name[s->client.tcp_state],
                              tcp_state_name[s->server.tcp_state]);
        tcp_update_wing(p, s, evt);

        // If parsers are ignored, no one moves the asm_seq, no point to
        // assemble or sequence the session.
        if (likely(FLAGS_TEST(p->flags, DPI_SESS_FLAG_SKIP_PARSER))) {
            p->this_wing->next_seq = end;
        }
        if (unlikely(tcph->fin && p->this_wing->next_seq == seq)) {
           p->this_wing->next_seq ++;
        }

        return;
    }

    if (len > 0) {
        clip_t *clip = asm_lookup(&p->this_wing->asm_cache, seq);
        if (clip != NULL) {
            if (clip->len == len) {
                // Both seq# and length have to be same to be considered as retransmission
                DEBUG_LOG(DBG_TCP, p, "TCP retransmission: seq=0x%x len=%u", seq, len);

                FLAGS_SET(p->flags, DPI_PKT_FLAG_CACHED |
                                    DPI_PKT_FLAG_SKIP_PARSER |
                                    DPI_PKT_FLAG_SKIP_PATTERN);
                dpi_set_action(p, DPI_ACTION_ALLOW);
                return;
            } else {
                DEBUG_LOG(DBG_TCP, p, "TCP replace cached packet: seq=0x%x len=%u\n",
                                      seq, clip->len);

                // remove the old packet cache
                asm_remove(&p->this_wing->asm_cache, clip, dpi_asm_remove);
            }
        }
    }

    uint32_t old_win = p->this_wing->tcp_win;
    p->this_wing->tcp_win = ntohs(tcph->th_win) << p->this_wing->tcp_wscale;
    // Ignore out-of-window packets
    if (!tcp_is_in_window(p)) {
        p->flags |= DPI_PKT_FLAG_SKIP_PARSER;
        return;
    }

    // Check small window DDos attack
    if (dpi_threat_status(DPI_THRT_TCP_SMALL_WINDOW) && dpi_is_client_pkt(p) &&
        !tcph->syn && !tcph->rst && !tcph->fin) {
        check_small_window_attack(p, old_win);
    }

    // TCP state transition
    int evt = tcp_update_state(p, s);
    DEBUG_LOG(DBG_TCP, p, "event: %s => C:%s S:%s\n",
                          tcp_event_name[evt],
                          tcp_state_name[s->client.tcp_state],
                          tcp_state_name[s->server.tcp_state]);
    tcp_update_wing(p, s, evt);

    DEBUG_LOG(DBG_TCP, NULL, "offset: seq=%u ack=%u\n",
              u32_distance(p->this_wing->init_seq, seq),
              u32_distance(p->that_wing->init_seq, ack));

    // Session action presents, no assembly
    if (unlikely(dpi_is_action_final(p, p->action) || dpi_is_action_final(p, s->action))) {
        return;
    }

    if (len > 0) {
        // If parsers are ignored, no one moves the asm_seq, no point to
        // assemble or sequence the session.
        if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_SKIP_PARSER)) {
            p->this_wing->next_seq = end;
        } else {
            tcp_assembly(p, s);

            // Update next_seq
            uint32_t next_seq = p->this_wing->next_seq;
            if (p->flags & DPI_PKT_FLAG_ASSEMBLED) {
                seq = p->asm_pkt.seq;
                end = p->asm_pkt.seq + p->asm_pkt.len;
            }
            if (unlikely(u32_lt(next_seq, seq))) {
                DEBUG_LOG(DBG_TCP, p, "TCP early packet: seq=0x%x next=0x%x\n", seq, next_seq);
                p->flags |= DPI_PKT_FLAG_SKIP_PARSER;
            } else if (likely(u32_lt(next_seq, end))) {
                p->this_wing->next_seq = end;
            } else {
                p->flags |= DPI_PKT_FLAG_SKIP_PARSER;
            }
        }
    }

    if (unlikely(tcph->fin && p->this_wing->next_seq == seq)) {
        p->this_wing->next_seq ++;
    }

    if (unlikely(tcph->ack && u32_gt(ack, p->that_wing->next_seq))) {
        DEBUG_LOG(DBG_TCP, p, "Acked unseen seq: ack=%u next=%u\n",
              u32_distance(p->that_wing->init_seq, ack),
              u32_distance(p->that_wing->init_seq, p->that_wing->next_seq));
        dpi_set_action(p, DPI_ACTION_BYPASS);
        asm_destroy(&p->this_wing->asm_cache, dpi_asm_remove);
        asm_destroy(&p->that_wing->asm_cache, dpi_asm_remove);
    }
}

void dpi_session_delete(dpi_session_t *s, int reason)
{
    DEBUG_LOG(DBG_SESSION, NULL, "session=%u reason=%d\n", s->id, reason);
    dpi_session_term_reason(s, reason);
    dpi_session_timer_remove(s);
    dpi_session_release(s);
}

void dpi_session_init(void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT | DBG_SESSION, NULL);

    rcu_map_init(&th_session4_map, 512, offsetof(dpi_session_t, node),
                 session4_match, session4_hash);
    rcu_map_init(&th_session6_map, 64, offsetof(dpi_session_t, node),
                 session6_match, session6_hash);
}

void dpi_session_proxymesh_init(void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT | DBG_SESSION, NULL);

    rcu_map_init(&th_session4_proxymesh_map, 64, offsetof(dpi_session_t, node),
                 session4_proxymesh_match, session4_proxymesh_hash);
    rcu_map_init(&th_session6_proxymesh_map, 32, offsetof(dpi_session_t, node),
                 session6_proxymesh_match, session6_proxymesh_hash);
}

