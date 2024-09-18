#include <string.h>

#include "utils/rcu_map.h"
#include "utils/timer_wheel.h"
#include "utils/helper.h"

#include "dpi/dpi_module.h"

void log_common(DPMsgThreatLog *log, int idx);
void log_packet_flags(DPMsgThreatLog *log, dpi_packet_t *p, bool flip);
void log_packet_detail(DPMsgThreatLog *log, dpi_packet_t *p, bool flip);
void log_session_flags(DPMsgThreatLog *log, dpi_session_t *sess);
void log_session_detail(DPMsgThreatLog *log, dpi_session_t *sess);

static meter_info_t meter_info[] = {
[DPI_METER_SYN_FLOOD]      {"syn_flood", METER_ID_SYN_FLOOD, DPI_THRT_TCP_FLOOD, true, false, true, false,
                            3, 30, 1, 200, 200},
[DPI_METER_ICMP_FLOOD]     {"icmp_flood", METER_ID_ICMP_FLOOD, DPI_THRT_ICMP_FLOOD, true, false, true, false,
                            3, 30, 1, 100, 100},
[DPI_METER_IP_SRC_SESSION] {"ip_src_session", METER_ID_IP_SRC_SESSION, DPI_THRT_IP_SRC_SESSION, false, false, true, true,
                            3, 30, 1, 2000, 2000},
[DPI_METER_TCP_NODATA]     {"tcp_nodata", METER_ID_TCP_NODATA, DPI_THRT_TCP_NODATA, true, false, true, false,
                            10, 0, 10, 10, 10},
};

meter_info_t *dpi_get_meter_info(int type)
{
    if (type >= DPI_METER_MAX) return NULL;
    return &meter_info[type];
}

static int meter_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_meter_t *m = STRUCT_OF(ht_node, dpi_meter_t, node);
    const dpi_meter_t *k = key;

    if (m->type != k->type) return false;

    meter_info_t *info = &meter_info[m->type];
    if (likely(info->per_dst) && memcmp(&m->ep_mac, &k->ep_mac, sizeof(k->ep_mac)) != 0) {
        return false;
    }
    if (info->per_src && memcmp(&m->peer_ip, &k->peer_ip, sizeof(m->peer_ip)) != 0) {
        return false;
    }

    return true;
}

static uint32_t meter_hash(const void *key)
{
    const dpi_meter_t *k = key;

    return sdbm_hash((uint8_t *)&k->ep_mac, sizeof(k->ep_mac)) +
           sdbm_hash((uint8_t *)&k->peer_ip, sizeof(k->peer_ip)) + k->type;
}

void dpi_meter_init(void)
{
    rcu_map_init(&th_meter_map, 512, offsetof(dpi_meter_t, node), meter_match, meter_hash);
}

static void make_key(dpi_meter_t *key, int type, uint8_t *ep_mac, uint8_t *peer_ip, bool ipv4)
{
    meter_info_t *info = &meter_info[type];

    key->type = type;
    if (likely(info->per_dst)) {
        mac_cpy(key->ep_mac, ep_mac);
    }
    if (likely(ipv4)) {
        if (info->per_src && peer_ip != NULL) {
            ip4_cpy((uint8_t *)&key->peer_ip.ip4, peer_ip);
        }
    } else {
        if (info->per_src && peer_ip != NULL) {
            memcpy(&key->peer_ip.ip6, peer_ip, 16);
        }
    }
}

static void meter_release(timer_entry_t *entry)
{
    dpi_meter_t *m = STRUCT_OF(entry, dpi_meter_t, ts_entry);
    meter_info_t *info = &meter_info[m->type];

    if (!info->rate && m->count != 0) {
        // "count" meter is released when count reaches 0
        timer_wheel_entry_insert(&th_timer, &m->ts_entry, th_snap.tick);
        return;
    }

    IF_DEBUG_LOG(DBG_TIMER | DBG_DDOS, NULL) {
        if (likely(m->log.EtherType == ntohs(ETH_P_IP))) {
            DEBUG_LOG_NO_FILTER("release: type=%s peer="DBG_IPV4_FORMAT"\n",
                                info->name, DBG_IPV4_TUPLE(m->peer_ip));
        } else {
            DEBUG_LOG_NO_FILTER("release: type=%s peer="DBG_IPV6_FORMAT"\n",
                                info->name, DBG_IPV6_TUPLE(m->peer_ip.ip6));
        }
    }

    th_counter.cur_meters --;
    rcu_map_del(&th_meter_map, m);
    free(m);
}

static dpi_meter_t *meter_alloc(int type, uint8_t *ep_mac, uint8_t *peer_ip, bool ipv4)
{
    dpi_meter_t *m;

    m = calloc(1, sizeof(*m));
    if (unlikely(m == NULL)) return NULL;

    make_key(m, type, ep_mac, peer_ip, ipv4);
    m->start_tick = th_snap.tick;

    th_counter.cur_meters ++;
    rcu_map_add(&th_meter_map, m, m);

    return m;
}

// Increment meter, return non-NULL if threshold is reached.
static dpi_meter_t *meter_inc(uint8_t type, uint8_t *ep_mac, uint8_t *peer_ip, bool ipv4, bool *fire, bool *create)
{
    dpi_meter_t key, *m;
    meter_info_t *info = &meter_info[type];

    memset(&key, 0, sizeof(key));
    make_key(&key, type, ep_mac, peer_ip, ipv4);
    m = rcu_map_lookup(&th_meter_map, &key);
    if (m == NULL) {
        m = meter_alloc(type, ep_mac, peer_ip, ipv4);
        if (unlikely(m == NULL)) return NULL;

        IF_DEBUG_LOG(DBG_DDOS, NULL) {
            if (likely(ipv4)) {
                DEBUG_LOG_NO_FILTER("alloc: type=%s peer="DBG_IPV4_FORMAT"\n",
                                    info->name, DBG_IPV4_TUPLE(m->peer_ip));
            }
        }

        timer_wheel_entry_init(&m->ts_entry);
        timer_wheel_entry_start(&th_timer, &m->ts_entry,
                                meter_release, info->timeout, th_snap.tick);
        *create = true;
    } else {
        timer_wheel_entry_refresh(&th_timer, &m->ts_entry, th_snap.tick);
        *create = false;
    }

    if (info->rate) {
        uint32_t span = th_snap.tick - m->start_tick;

        if (span >= info->span) {
            m->last_count = m->count;
            m->count *= (float)(info->span - 1) / span;
            m->start_tick = th_snap.tick - (info->span - 1);
        } else if (m->count > info->upper_limit) {
            // count if reached before the span is reached, for example, a burst of incident. !! span can be 0.
            m->last_count = m->count / (span + 1);
            m->count *= (float)(info->span - span) / info->span;
        }

        m->count ++;

        if (likely(m->last_count < info->lower_limit)) {
            FLAGS_UNSET(m->flags, DPI_METER_FLAG_ON);
            *fire = false;
            return m;
        } else if (m->last_count >= info->upper_limit) {
            m->log_count ++;
            FLAGS_SET(m->flags, DPI_METER_FLAG_ON);
            *fire = true;
            return m;
        } else if (m->flags & DPI_METER_FLAG_ON) {
            m->log_count ++;
            *fire = true;
            return m;
        }
    } else {
        m->count ++;
        if (unlikely(m->count >= info->upper_limit)) {
            m->log_count ++;
            *fire = true;
            return m;
        }
    }

    *fire = false;
    return m;
}

static void meter_dec(uint8_t type, uint8_t *ep_mac, uint8_t *peer_ip, bool ipv4)
{
    dpi_meter_t key, *m;
    meter_info_t *info = &meter_info[type];

    if (info->rate) return;

    memset(&key, 0, sizeof(key));
    make_key(&key, type, ep_mac, peer_ip, ipv4);
    m = rcu_map_lookup(&th_meter_map, &key);
    if (unlikely(m == NULL)) return;

    timer_wheel_entry_refresh(&th_timer, &m->ts_entry, th_snap.tick);

    m->count --;
}

int dpi_meter_packet_inc(uint8_t type, dpi_packet_t *p)
{
    meter_info_t *info = &meter_info[type];
    uint32_t log_id = info->log_id;

    if (!dpi_threat_status(log_id)) return DPI_METER_ACTION_NONE;
    // if (!(p->flags & DPI_PKT_FLAG_INGRESS)) return DPI_METER_ACTION_NONE;

    bool ipv4, fire = false, create = false;
    uint8_t *peer_ip;

    if (likely(p->eth_type == ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        ipv4 = true;
        peer_ip = (uint8_t *)&iph->saddr;
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
        peer_ip = (uint8_t *)&ip6h->ip6_src;
    }

    dpi_meter_t *m = meter_inc(type, p->ep_mac, peer_ip, ipv4, &fire, &create);

    if (likely(m != NULL)) {
        if (unlikely(create || fire)) {
            DPMsgThreatLog *log = &m->log;
            memset(log, 0, sizeof(*log));
            log_common(log, log_id);
            log_packet_flags(log, p, false);
            log_packet_detail(log, p, false);
        }

        if (unlikely(fire)) {
            if (th_snap.tick - m->last_log >= info->log_timeout && m->log_count > 0) {
                dpi_ddos_log(info->log_id, m, "Packet rate %u(pps) exceeds the shreshold %u(pps)", m->last_count, info->lower_limit);
                m->last_log = th_snap.tick;
                m->log_count = 0;
            }

            th_counter.drop_meters ++;

            dpi_set_action(p, DPI_ACTION_DROP);
            return DPI_METER_ACTION_CLEAR;
        }
    }

    return DPI_METER_ACTION_NONE;
}

int dpi_meter_synflood_inc(dpi_packet_t *p)
{
    meter_info_t *info = &meter_info[DPI_METER_SYN_FLOOD];
    uint32_t log_id = DPI_THRT_TCP_FLOOD;

    if (!dpi_threat_status(log_id)) return DPI_METER_ACTION_NONE;
    if (!(p->flags & DPI_PKT_FLAG_INGRESS)) return DPI_METER_ACTION_NONE;

    bool fire = false, create = false;
    dpi_meter_t *m = meter_inc(DPI_METER_SYN_FLOOD, p->ep_mac, NULL, p->eth_type == ETH_P_IP, &fire, &create);
    if (likely(m != NULL)) {
        if (unlikely(create || fire)) {
            DPMsgThreatLog *log = &m->log;
            memset(log, 0, sizeof(*log));
            log_common(log, log_id);
            log_packet_flags(log, p, false);
            log_packet_detail(log, p, false);
        }

        if (unlikely(fire)) {
            // TODO: when to log?
            // not to increase meter drop count

            if (!p->ep->tap) {
                if (th_snap.tick - m->last_log >= info->log_timeout && m->log_count > 0) {
                    dpi_ddos_log(info->log_id, m, "TCP SYN Packet rate %u(pps) exceeds the shreshold %u(pps)", m->last_count, info->lower_limit);
                    m->last_log = th_snap.tick;
                    m->log_count = 0;
                }

                th_counter.drop_meters ++;
                // TODO: SYN proxy logic goes here
                dpi_set_action(p, DPI_ACTION_DROP);
                return DPI_METER_ACTION_CLEAR;
            }
        }
    }

    return DPI_METER_ACTION_NONE;
}

int dpi_meter_session_inc(dpi_packet_t *p, dpi_session_t *s)
{
    if (!(s->flags & DPI_SESS_FLAG_INGRESS)) return DPI_METER_ACTION_NONE;

    bool ipv4 = FLAGS_TEST(s->flags, DPI_SESS_FLAG_IPV4);
    uint8_t *peer_ip = (uint8_t *)&s->client.ip;

    if (dpi_threat_status(DPI_THRT_IP_SRC_SESSION)) {
        bool fire = false, create = false;
        dpi_meter_t *m = meter_inc(DPI_METER_IP_SRC_SESSION, s->server.mac, peer_ip, ipv4, &fire, &create);
        if (likely(m != NULL)) {
            FLAGS_SET(s->meter_flags, DPI_SESS_METER_FLAG_IP_SESSION);

            if (unlikely(create || fire)) {
                DPMsgThreatLog *log = &m->log;
                memset(log, 0, sizeof(*log));
                log_common(log, DPI_THRT_IP_SRC_SESSION);
                log_packet_flags(log, p, false);
                log_packet_detail(log, p, false);
            }

            if (unlikely(fire)) {
                // Aggregate log
                meter_info_t *info = &meter_info[m->type];
                if (th_snap.tick - m->last_log >= info->log_timeout && m->log_count > 0) {
                    if (likely(ipv4)) {
                        dpi_ddos_log(info->log_id, m,
                                     "Session rate %u from "DBG_IPV4_FORMAT" exceeds the shreshold %u",
                                     m->count, DBG_IPV4_TUPLE(m->peer_ip.ip4), info->lower_limit);
                    } else {
                        dpi_ddos_log(info->log_id, m,
                                     "Session rate %u from "DBG_IPV6_FORMAT" exceeds the shreshold %u",
                                     m->count, DBG_IPV6_TUPLE(m->peer_ip.ip6), info->lower_limit);
                    }

                    m->last_log = th_snap.tick;
                    m->log_count = 0;
                }

                th_counter.drop_meters ++;

                if (!FLAGS_TEST(s->flags, DPI_SESS_FLAG_TAP)) {
                    return DPI_METER_ACTION_CLEAR;
                }
            }
        }
    }

    return DPI_METER_ACTION_NONE;
}

void dpi_meter_session_dec(dpi_session_t *s)
{
    if (!(s->flags & DPI_SESS_FLAG_INGRESS)) return;

    bool ipv4 = FLAGS_TEST(s->flags, DPI_SESS_FLAG_IPV4);
    uint8_t *peer_ip = (uint8_t *)&s->client.ip;

    if (FLAGS_TEST(s->meter_flags, DPI_SESS_METER_FLAG_IP_SESSION)) {
        meter_dec(DPI_METER_IP_SRC_SESSION, s->server.mac, peer_ip, ipv4);
    }
}

bool dpi_meter_session_rate(uint8_t type, dpi_session_t *s)
{
    meter_info_t *info = &meter_info[type];
    uint32_t log_id = info->log_id;

    if (!dpi_threat_status(log_id)) return DPI_METER_ACTION_NONE;

    bool ipv4 = FLAGS_TEST(s->flags, DPI_SESS_FLAG_IPV4);
    uint8_t *ep_mac;
    uint8_t *peer_ip;

    if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS)) {
        ep_mac = s->server.mac;
        peer_ip = (uint8_t *)&s->server.ip;
    } else {
        ep_mac = s->client.mac;
        peer_ip = (uint8_t *)&s->client.ip;
    }

    bool fire = false, create = false;
    dpi_meter_t *m = meter_inc(type, ep_mac, peer_ip, ipv4, &fire, &create);
    if (likely(m != NULL)) {
        if (unlikely(create || fire)) {
            DPMsgThreatLog *log = &m->log;
            memset(log, 0, sizeof(*log));
            log_common(log, log_id);
            log_session_flags(log, s);
            log_session_detail(log, s);
        }
    }

    return fire;
}
