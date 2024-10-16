#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "urcu.h"
#include "debug.h"
#include "utils/rcu_map.h"
#include "dpi/dpi_module.h"

dpi_fqdn_hdl_t *g_fqdn_hdl = NULL;
extern bool cmp_mac_prefix(void *m1, void *prefix);

static int policy_match_ipv4_fqdn_code(dpi_fqdn_hdl_t *fqdn_hdl, uint32_t ip, dpi_policy_hdl_t *hdl, dpi_rule_key_t *key,
                                     int is_ingress, dpi_policy_desc_t *desc2, dpi_packet_t *p);
static bool _dpi_policy_implicit_default(dpi_policy_hdl_t *hdl, dpi_policy_desc_t *desc);
static void _dpi_policy_chk_unknown_ip(dpi_policy_hdl_t *hdl, uint32_t sip, uint32_t dip,
                                    uint8_t iptype, dpi_policy_desc_t **pol_desc);
static void _dpi_policy_chk_nbe(dpi_packet_t *p, uint32_t sip, uint32_t dip, int is_ingress, dpi_policy_hdl_t *hdl, dpi_policy_desc_t **pol_desc);

/*
 * -----------------------------------------------------
 * --- unknown ip description cache definition ----------
 * -----------------------------------------------------
 */
#define UNKNOWN_IP_CACHE_TIMEOUT 600 //sec
#define POLICY_DESC_VER_CHG_MAX 60 //sec
#define UNKNOWN_IP_TRY_COUNT 10 //10 times
#define HOST_IP_TRY_COUNT 3 //3 times
#define EXT_IP_TRY_COUNT 2 //2 times
typedef struct dpi_unknown_ip_desc_ {
    uint32_t sip;
    uint32_t dip;
    uint16_t hdl_ver;
} dpi_unknown_ip_desc_t;

typedef struct dpi_unknown_ip_cache_ {
    struct cds_lfht_node node;
    timer_entry_t ts_entry;

    dpi_unknown_ip_desc_t desc;
    uint32_t start_hit;
    uint32_t last_hit;
    uint8_t try_cnt;
} dpi_unknown_ip_cache_t;

static int unknown_ip_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_unknown_ip_cache_t *c = STRUCT_OF(ht_node, dpi_unknown_ip_cache_t, node);
    const dpi_unknown_ip_desc_t *k = key;

    return (c->desc.sip == k->sip && c->desc.dip == k->dip) ? true : false;
}

static uint32_t unknown_ip_hash(const void *key)
{
    const dpi_unknown_ip_desc_t *k = key;

    return sdbm_hash((uint8_t *)&k->sip, 4) + sdbm_hash((uint8_t *)&k->dip, 4);
}

static void unknown_ip_release(timer_entry_t *entry)
{
    dpi_unknown_ip_cache_t *c = STRUCT_OF(entry, dpi_unknown_ip_cache_t, ts_entry);
    rcu_map_del(&th_unknown_ip_map, c);
    free(c);
}

void dpi_unknown_ip_init(void)
{
    rcu_map_init(&th_unknown_ip_map, 64, offsetof(dpi_unknown_ip_cache_t, node), unknown_ip_match, unknown_ip_hash);
}

static void add_unknown_ip_cache(dpi_unknown_ip_desc_t *desc, dpi_unknown_ip_desc_t *key, uint8_t iptype, bool ext)
{
    dpi_unknown_ip_cache_t *cache = calloc(1, sizeof(*cache));
    if (cache != NULL) {
        memcpy(&cache->desc, desc, sizeof(*desc));
        cache->start_hit = th_snap.tick;
        cache->last_hit = th_snap.tick;
        if (iptype == DP_IPTYPE_HOSTIP || iptype == DP_IPTYPE_TUNNELIP) {
            cache->try_cnt = HOST_IP_TRY_COUNT;
        } else {
            cache->try_cnt = UNKNOWN_IP_TRY_COUNT;
            if (ext) {
                cache->try_cnt = EXT_IP_TRY_COUNT;
            }
        }
        rcu_map_add(&th_unknown_ip_map, cache, key);

        timer_wheel_entry_init(&cache->ts_entry);
        timer_wheel_entry_start(&th_timer, &cache->ts_entry,
                                unknown_ip_release, UNKNOWN_IP_CACHE_TIMEOUT, th_snap.tick);
    }
}

static void refresh_unknown_ip_cache(dpi_unknown_ip_cache_t *cache, uint16_t thdl_ver, uint8_t try_cnt)
{
    cache->try_cnt = try_cnt;
    cache->desc.hdl_ver = thdl_ver;
    //restart timestamp
    cache->start_hit = th_snap.tick;
    cache->last_hit = th_snap.tick;

    timer_wheel_entry_refresh(&th_timer, &cache->ts_entry, th_snap.tick);
}

static void update_unknown_ip_cache(dpi_unknown_ip_cache_t *cache)
{
    timer_wheel_entry_refresh(&th_timer, &cache->ts_entry, th_snap.tick);
    //update timestamp
    cache->last_hit = th_snap.tick;
}

/*
 * -----------------------------------------------------
 * --- Policy rule definition --------------------------
 * -----------------------------------------------------
 */
static int dpi_policy_lookup_by_key(dpi_policy_hdl_t *hdl, uint32_t sip, uint32_t dip,
                             uint16_t dport, uint16_t proto, uint32_t app,
                             int is_ingress, dpi_policy_desc_t *desc, dpi_packet_t *p);
static int dpi_rule_add(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l, dpi_rule_key_t *key_h,
                 int app_num, dpi_policy_app_rule_t *app_rules,
                 int dir, dpi_policy_desc_t *desc);

/*----------------------------------------------------*/

static int rule_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_rule_t *s = STRUCT_OF(ht_node, dpi_rule_t, node);
    const dpi_rule_key_t *k = key;
    return memcmp(&s->key, k, sizeof(dpi_rule_key_t))?0:1;
}

static uint32_t rule_hash(const void *key)
{
    const dpi_rule_key_t *k = key;
    return sdbm_hash((uint8_t *)k, sizeof(dpi_rule_key_t));
}

static void rule_key_cpy(dpi_rule_key_t *k1, dpi_rule_key_t *k2)
{
    memcpy(k1, k2, sizeof(dpi_rule_key_t));
}

static void policy_desc_cpy(dpi_policy_desc_t *d1, dpi_policy_desc_t *d2)
{
    memcpy(d1, d2, sizeof(dpi_policy_desc_t));
}

static int rule_key_comp(dpi_rule_key_t *k1, dpi_rule_key_t *k2)
{
    return memcmp(k1, k2, sizeof(dpi_rule_key_t));
}

static int range_rule_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_range_rule_t *s = STRUCT_OF(ht_node, dpi_range_rule_t, node);
    const dpi_range_rule_key_t *k = key;

    return memcmp(&s->key, k, sizeof(dpi_range_rule_key_t))?0:1;
}

static uint32_t range_rule_hash(const void *key)
{
    const dpi_range_rule_key_t *k = key;
    return sdbm_hash((uint8_t *)k, sizeof(dpi_range_rule_key_t));
}

static void range_rule_key_cpy(dpi_range_rule_key_t *k1, dpi_range_rule_key_t *k2)
{
    memcpy(k1, k2, sizeof(dpi_range_rule_key_t));
}

#define IS_X_IN_RANGE(x, y, z) ((x >= y) && (x <= z))
static int rule_key_in_range(dpi_range_rule_item_t *item, dpi_rule_key_t *k)
{
    if (IS_X_IN_RANGE(k->dport, item->key_l.dport, item->key_h.dport) &&
        IS_X_IN_RANGE(ntohl(k->sip), ntohl(item->key_l.sip), ntohl(item->key_h.sip)) &&
        IS_X_IN_RANGE(ntohl(k->dip), ntohl(item->key_l.dip), ntohl(item->key_h.dip)) &&
        IS_X_IN_RANGE(k->app, item->key_l.app, item->key_h.app)) {
        return 1;
    } else {
        return 0;
    }
}

void dpi_add_default_policy(dpi_policy_hdl_t *hdl)
{
    dpi_rule_key_t key_l, key_h;
    dpi_policy_desc_t desc;

    memset(&key_l, 0, sizeof(key_l));
    memset(&key_h, 0, sizeof(key_h));
    memset(&desc, 0, sizeof(desc));

    /* Allow all ICMP traffic */
    key_l.sip = 0;
    key_l.dip = 0;
    key_l.dport = 0;
    key_l.proto = IPPROTO_ICMP;
    key_h.sip = 0xffffffff;
    key_h.dip = 0xffffffff;
    key_h.dport = 0;
    key_h.proto = IPPROTO_ICMP;
    desc.action = DP_POLICY_ACTION_ALLOW;
    desc.id = DEFAULT_ICMP_PASS_POLICY_ID;
    desc.order = 0xffffffff;
    dpi_rule_add(hdl, &key_l, &key_h, 0, NULL, POLICY_RULE_DIR_NONE, &desc);
}

static dpi_policy_hdl_t *dpi_policy_hdl_init(int def_action)
{
    dpi_policy_hdl_t *hdl;
    hdl = calloc(sizeof(dpi_policy_hdl_t), 1);
    if (!hdl) {
        DEBUG_ERROR(DBG_POLICY, "Out of memory!");
        return NULL;

    }
    DEBUG_POLICY("%p, def_action=%d\n", hdl, def_action);
    rcu_map_init(&(hdl->policy_map), 128, offsetof(dpi_rule_t, node),
                 rule_match, rule_hash);

    rcu_map_init(&(hdl->range_policy_map), 16, offsetof(dpi_range_rule_t, node),
                 range_rule_match, range_rule_hash);
    hdl->def_action = def_action;
    return hdl;
}

bool iter_delete_one_rule(struct cds_lfht_node *ht_node, void *args)
{
    dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)args;
    dpi_rule_t *r = (dpi_rule_t *)ht_node;
    rcu_map_del(&hdl->policy_map, ht_node);
    free(r);
    th_counter.type1_rules--;
    return 0;
}

bool iter_delete_one_range_rule(struct cds_lfht_node *ht_node, void *args)
{
    dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)args;
    dpi_range_rule_t *r = (dpi_range_rule_t *)ht_node;
    dpi_range_rule_item_t  *p, *prev;
    rcu_map_del(&hdl->range_policy_map, ht_node);
    p = r->range_rule_list;
    while (p) {
        prev = p;
        p = p->next;
        free(prev);
        th_counter.type2_rules--;
    }
    free(r);
    return 0;
}

void dpi_policy_hdl_destroy(dpi_policy_hdl_t *hdl)
{
    DEBUG_POLICY("%p, ref_cnt %d \n", hdl, hdl->ref_cnt);
    if (hdl->ref_cnt > 1) {
        hdl->ref_cnt--;
        return;
    }
    rcu_map_for_each(&hdl->policy_map, iter_delete_one_rule, hdl);
    rcu_map_for_each(&hdl->range_policy_map, iter_delete_one_range_rule, hdl);
    rcu_map_destroy(&hdl->policy_map);
    rcu_map_destroy(&hdl->range_policy_map);
    free(hdl);
}

static int get_range_key(dpi_rule_key_t *key_l, dpi_rule_key_t *key_h, int dir,
                         dpi_range_rule_key_t *key)
{
    if (key_l->proto != key_h->proto) {
        DEBUG_ERROR(DBG_POLICY, "policy not valid! key_l "
                    DP_RULE_STR "key_h " DP_RULE_STR "\n",
                    DP_RULE_KEY(key_l), DP_RULE_KEY(key_h));
        return -1;
    }
    memset(key, 0, sizeof(dpi_range_rule_key_t));
    key->proto = key_l->proto;
    switch (dir) {
    case POLICY_RULE_DIR_INGRESS:
        key->ip = key_l->dip;
        key->flag = DP_RANGE_RULE_INGRESS;
        break;
    case POLICY_RULE_DIR_EGRESS:
        key->ip = key_l->sip;
        key->flag = DP_RANGE_RULE_EGRESS;
        break;
    case POLICY_RULE_DIR_NONE:
        key->ip = 0;
        key->flag = 0;
        break;
    default:
        DEBUG_ERROR(DBG_POLICY, "policy not valid! key_l "
                    DP_RULE_STR "key_h " DP_RULE_STR "\n",
                    DP_RULE_KEY(key_l), DP_RULE_KEY(key_h));
        return -1;
    }
    return 0;
}

static int dpi_range_rule_add(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l,
                              dpi_rule_key_t *key_h, int dir, dpi_policy_desc_t *desc,
                              dpi_policy_desc_t *exist_desc)
{
    dpi_range_rule_key_t key;
    dpi_range_rule_t  *r;
    dpi_range_rule_item_t  *item, *p, *prev;

    if (get_range_key(key_l, key_h, dir, &key)) {
        return -1;
    }

    r = rcu_map_lookup(&hdl->range_policy_map, &key);
    if (!r) {
        r = (dpi_range_rule_t *)calloc(1, sizeof(dpi_range_rule_t));
        if (!r) {
            DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
            return -1;
        }
        range_rule_key_cpy(&r->key, &key);
        rcu_map_add(&hdl->range_policy_map, r, &key);
    }

    item = (dpi_range_rule_item_t *)calloc(1, sizeof(dpi_range_rule_item_t));
    if (!item) {
        DEBUG_ERROR(DBG_POLICY, "OOM 2!!!\n");
        return -1;
    } else {
        policy_desc_cpy(&item->desc, desc);
        rule_key_cpy(&item->key_l, key_l);
        rule_key_cpy(&item->key_h, key_h);
        item->next = NULL;
    }

    p = r->range_rule_list;
    prev = p;
    while (p) {
        if ((rule_key_comp(&p->key_l, key_l) == 0) && (rule_key_comp(&p->key_h, key_h) == 0)) {
            break;
        } else {
            prev = p;
            p = p->next;
        }
    }

    if (p) {
        /*
        DEBUG_POLICY("Rule already exist!!!\n");
        DEBUG_POLICY("key_l " DP_RULE_STR "key_h " DP_RULE_STR
                    "old:"DP_POLICY_DESC_STR "new:" DP_POLICY_DESC_STR "\n",
                    DP_RULE_KEY(key_l), DP_RULE_KEY(key_h),
                    DP_POLICY_DESC(((&(p->desc)))), DP_POLICY_DESC(desc));
        */
        policy_desc_cpy(exist_desc, &p->desc);
        free(item);
        return 0;
    } else if (prev) {
        /* append at the end */
        prev->next = item;
    } else {
        /* Add as the first item */
        r->range_rule_list = item;
    }
    th_counter.type2_rules++;
    return 1;
}

/*
static int dpi_range_rule_del_one(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l,
                                  dpi_rule_key_t *key_h, int dir)
{
    dpi_range_rule_key_t key;
    dpi_range_rule_t  *r;
    dpi_range_rule_item_t *p, *prev;

    if (get_range_key(key_l, key_h, dir, &key)) {
        return -1;
    }

    r = rcu_map_lookup(&hdl->range_policy_map, &key);
    if (!r) {
        return -1;
    }

    p = r->range_rule_list;
    prev = p;
    while (p) {
        if ((rule_key_comp(&p->key_l, key_l) == 0) && (rule_key_comp(&p->key_h, key_h) == 0)) {
            break;
        } else {
            prev = p;
            p = p->next;
        }
    }

    if (!p) {
        return -1;
    }

    if (prev) {
        prev->next = p->next;
    } else {
        r->range_rule_list = p->next;
    }
    free(p);
    return 0;
}
*/

static int dpi_rule_add_one(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l,
                            dpi_rule_key_t *key_h, int dir, dpi_policy_desc_t *desc,
                            dpi_policy_desc_t *exist_desc)
{
    if (key_h == NULL) {
        dpi_rule_t  *r;
        dpi_policy_lookup_by_key(hdl, key_l->sip, key_l->dip,
                                 key_l->dport, key_l->proto, key_l->app,
                                 dir == POLICY_RULE_DIR_INGRESS?1:0,
                                 exist_desc, NULL);
        if (exist_desc->id != 0) {
            DEBUG_POLICY("key_l " DP_RULE_STR
                       "old:"DP_POLICY_DESC_STR "new:" DP_POLICY_DESC_STR"- same key!\n",
                       DP_RULE_KEY(key_l),
                       DP_POLICY_DESC((exist_desc)), DP_POLICY_DESC(desc));
            return 0;
        }

        r = (dpi_rule_t *)calloc(1, sizeof(dpi_rule_t));
        if (!r) {
            DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
            return -1;
        }
        rule_key_cpy(&r->key, key_l);
        policy_desc_cpy(&r->desc, desc);
        rcu_map_add(&hdl->policy_map, r, key_l);
        th_counter.type1_rules++;
        return 1;
    } else {
        //DEBUG_POLICY("key_l " DP_RULE_STR "key_h " DP_RULE_STR DP_POLICY_DESC_STR "dir %d\n",
        //           DP_RULE_KEY(key_l), DP_RULE_KEY(key_h), DP_POLICY_DESC(desc), dir);
        return dpi_range_rule_add(hdl, key_l, key_h, dir, desc, exist_desc);
    }
}

/*
int dpi_rule_del_one(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l, dpi_rule_key_t *key_h, int dir)
{

    if (key_h == NULL) {
        dpi_rule_t  *r = rcu_map_lookup(&hdl->policy_map, key_l);
        DEBUG_POLICY("key_l " DP_RULE_STR "\n", DP_RULE_KEY(key_l));
        if (r) {
            rcu_map_del(&hdl->policy_map, r);
            free(r);
        }
        return 0;
    } else {
        DEBUG_POLICY("key_l " DP_RULE_STR "key_h " DP_RULE_STR "\n",
                   DP_RULE_KEY(key_l), DP_RULE_KEY(key_h));
        return dpi_range_rule_del_one(hdl, key_l, key_h, dir);
    }
}
*/

static int dpi_add_app_rule(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l, dpi_rule_key_t *key_h,
                            dpi_policy_app_rule_t *app_rule, int dir, dpi_policy_desc_t *desc,
                            dpi_policy_desc_t *exist_desc)
{
    int use_key = 0;
    dpi_rule_key_t key;
    dpi_policy_desc_t app_desc;

    key_l->app = app_rule->app;
    if (key_l->app) {
        if (key_h) {
            key_h->app = key_l->app;
        }
    } else {
        // application any
        if (key_h) {
            key_h->app = 0xffffffff;
        } else {
            memcpy(&key, key_l, sizeof(dpi_rule_key_t));
            key.app = 0xffffffff;
            use_key = 1;
        }
    }
    app_desc.id = app_rule->rule_id;
    app_desc.action = app_rule->action;
    app_desc.hdl_ver = 0;
    app_desc.flags = desc->flags;
    app_desc.order = desc->order;
    return dpi_rule_add_one(hdl, key_l, use_key?&key:key_h, dir, &app_desc, exist_desc);
}

int dpi_rule_add(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key_l, dpi_rule_key_t *key_h,
                 int app_num, dpi_policy_app_rule_t *app_rules,
                 int dir, dpi_policy_desc_t *desc)
{
    int ret;
    dpi_policy_desc_t exist_desc;

    memset(&exist_desc, 0, sizeof(exist_desc));
    ret = dpi_rule_add_one(hdl, key_l, key_h, dir, desc, &exist_desc);
    if (ret < 0) {
        return ret;
    } else if (ret == 0 && exist_desc.id > 0) {
        // If the exising rule is a check_app rule, it shouldn't override
        // the new rule
        if (exist_desc.action != DP_POLICY_ACTION_CHECK_APP) {
            return ret;
        } else if (desc->action != DP_POLICY_ACTION_CHECK_APP) {
            // install an app any rule
            dpi_policy_app_rule_t app_rule;
            app_rule.app = 0;
            app_rule.action = desc->action;
            app_rule.rule_id = desc->id;
            ret = dpi_add_app_rule(hdl, key_l, key_h, &app_rule, dir, desc, &exist_desc);
        }
    } else if (ret > 0) {
        //newly added rule match any application
        if (desc->id > 0 && desc->action != DP_POLICY_ACTION_CHECK_APP) {
            // install an app any rule
            dpi_policy_app_rule_t app_rule;
            app_rule.app = 0;
            app_rule.action = desc->action;
            app_rule.rule_id = desc->id;
            ret = dpi_add_app_rule(hdl, key_l, key_h, &app_rule, dir, desc, &exist_desc);
        }
    }

    if (app_num > 0) {
        int i;
        for (i = 0; i < app_num; i++) {
            if (dpi_add_app_rule(hdl, key_l, key_h, &app_rules[i], dir, desc, &exist_desc) == 1) {
                ret++;
            }
        }
        // recover the values as the caller can reuse the same key_l and key_h for proto any case
        key_l->app = 0;
        if (key_h) {
            key_h->app = 0;
        }
    }
    return ret;
}

static dpi_range_rule_item_t *dpi_range_rule_match(dpi_range_rule_t *r, dpi_rule_key_t *key)
{
    dpi_range_rule_item_t *item = r->range_rule_list;
    while (item) {
/*
        DEBUG_POLICY("Found rule " DP_RULE_STR "-" DP_RULE_STR DP_POLICY_DESC_STR "%d\n",
                     DP_RULE_KEY((&item->key_l)),
                     DP_RULE_KEY((&item->key_h)), DP_POLICY_DESC((&item->desc)));
*/
        if (rule_key_in_range(item, key)) {
            break;
        } else {
            item = item->next;
        }
    }
    return item;
}

int dpi_policy_lookup(dpi_packet_t *p, dpi_policy_hdl_t *hdl, uint32_t app,
                      bool to_server, bool xff, dpi_policy_desc_t *desc, uint32_t xff_replace_dst_ip)
{
    struct iphdr *iph;
    int not_support = 0;
    uint32_t sip, dip;
    uint16_t dport, proto;
    int is_ingress;
    uint8_t iptype;
    bool inPolicyAddr = false;

    //for ip obtained from xff, clear until
    //compare with original ip
    if (!xff) {
        memset(desc, 0, sizeof(dpi_policy_desc_t));
    }
    /* only support ipv4 policy for now */
    switch (p->eth_type) {
    case ETH_P_IP:
        break;
    default:
        not_support = 1;
        break;
    }

    if (unlikely(not_support)) {
        goto exit;
    }

    switch (p->ip_proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        dport = to_server ? p->dport : p->sport;
        break;
    case IPPROTO_ICMP:
        dport = 0;
        break;
    default:
        not_support = 1;
        break;
    }

    if (unlikely(not_support)) {
        goto exit;
    }

    iph = (struct iphdr *)(p->pkt + p->l3);
    sip = to_server?iph->saddr:iph->daddr;
    dip = to_server?iph->daddr:iph->saddr;
    if (xff) {
        if (sip != p->session->xff_client_ip) {
            sip = p->session->xff_client_ip;
            if (p->session->xff_port > 0) {
                dport = p->session->xff_port;
            } else {
                //no x-forwarded-port in header
                //use server port on workload
                p->session->xff_port = dport;
            }
            DEBUG_POLICY("change dport to:%u, sip to x-forwarded-for:"DBG_IPV4_FORMAT"\n",dport, DBG_IPV4_TUPLE(sip));
            if (xff_replace_dst_ip > 0) {
                DEBUG_POLICY("change dst ip from :"DBG_IPV4_FORMAT" to :"DBG_IPV4_FORMAT"\n",DBG_IPV4_TUPLE(dip), DBG_IPV4_TUPLE(xff_replace_dst_ip));
                dip = xff_replace_dst_ip;
            }
            memset(desc, 0, sizeof(dpi_policy_desc_t));
        } else {
            //no need to do policy match if xff ip is same as original
            //keep original desc intact
            goto exit;
        }
    }
    proto = p->ip_proto;
    is_ingress = to_server?p->flags & DPI_PKT_FLAG_INGRESS:!(p->flags & DPI_PKT_FLAG_INGRESS);
    DEBUG_POLICY("hdl:%p proto:%u client:"DBG_IPV4_FORMAT" server:"DBG_IPV4_FORMAT":%u app:%u ingress:%d to_server:%d\n",
                 hdl, proto, DBG_IPV4_TUPLE(sip), DBG_IPV4_TUPLE(dip), dport, app, is_ingress, to_server);
    dpi_policy_lookup_by_key(hdl, sip, dip, dport, proto, app, is_ingress, desc, p);

    _dpi_policy_chk_nbe(p, sip, dip, is_ingress, hdl, &desc);

    if ((desc->flags & POLICY_DESC_INTERNAL)) {
        if (is_ingress) {
            iptype = dpi_ip4_iptype(sip);
        } else {
            iptype = dpi_ip4_iptype(dip);
        }
        if (_dpi_policy_implicit_default(hdl, desc)) {
            if (is_ingress) {
                if (iptype == DP_IPTYPE_HOSTIP || iptype == DP_IPTYPE_TUNNELIP) {
                    inPolicyAddr = dpi_is_policy_addr(dip);
                    //we still need to consider newly added node
                    if (inPolicyAddr) {
                        inPolicyAddr = dpi_is_policy_addr(sip);
                    }
                } else {
                    inPolicyAddr = dpi_is_policy_addr(sip);
                }
            } else {
                if (iptype == DP_IPTYPE_HOSTIP || iptype == DP_IPTYPE_TUNNELIP) {
                    inPolicyAddr = dpi_is_policy_addr(sip);
                    //we still need to consider newly added node
                    if (inPolicyAddr) {
                        inPolicyAddr = dpi_is_policy_addr(dip);
                    }
                } else {
                    inPolicyAddr = dpi_is_policy_addr(dip);
                }
            }
            if (!inPolicyAddr) {
                _dpi_policy_chk_unknown_ip(hdl, sip, dip, iptype, &desc);
            }
        }
        if (iptype == DP_IPTYPE_UWLIP) {
            desc->flags |= POLICY_DESC_UWLIP;
        }
    } else {
        if (_dpi_policy_implicit_default(hdl, desc)) {
            if (is_ingress) {
                inPolicyAddr = dpi_is_policy_addr(dip);
            } else {
                inPolicyAddr = dpi_is_policy_addr(sip);
            }
            if (!inPolicyAddr) {
                if (is_ingress) {
                    _dpi_policy_chk_unknown_ip(hdl, 0, dip, DP_IPTYPE_NONE, &desc);
                } else {
                    _dpi_policy_chk_unknown_ip(hdl, sip, 0, DP_IPTYPE_NONE, &desc);
                }
            }
        }
    }

    //(CVE-2020-8554: MitM Vulnerability in Kubernetes)
    //POD inside cluster connect to server service
    //with type externalIP has MITM (man in the middle)
    //risk, treat it as a Threat/Vulnerability
    if (desc->flags & POLICY_DESC_SVC_EXTIP) {
        dpi_threat_trigger(DPI_THRT_K8S_EXTIP_MITM, p, "CVE-2020-8554: Man in the Middle");
    }

exit:
    DEBUG_POLICY("return " DP_POLICY_DESC_STR "\n", DP_POLICY_DESC(desc));
    return 0;
}

static void _dpi_policy_chk_nbe(dpi_packet_t *p, uint32_t sip, uint32_t dip, int is_ingress, dpi_policy_hdl_t *hdl, dpi_policy_desc_t **pol_desc)
{
    if (hdl == NULL || pol_desc == NULL) return;
    if (!p || !p->ep) return;

    dpi_policy_desc_t *desc = *pol_desc;
    if (desc->action == DP_POLICY_ACTION_CHECK_NBE) {
        //if ns_boundary is enforced, we need to adjust
        //action for corresponding policy mode
        if (p->ep->nbe) {
            //set policy id to 0 plus flag to indicate
            //it is a cross namespace violation
            desc->id = 0;
            desc->flags |= POLICY_DESC_CHK_NBE;
            if (hdl->def_action == DP_POLICY_ACTION_LEARN) {//discover
                desc->action = DP_POLICY_ACTION_VIOLATE;
            }
            if (hdl->def_action == DP_POLICY_ACTION_VIOLATE) {//monitor
                desc->action = DP_POLICY_ACTION_VIOLATE;
            }
            if (hdl->def_action == DP_POLICY_ACTION_DENY) {//protect
                desc->action = DP_POLICY_ACTION_DENY;
            }
        } else {
            //if ns_boundary is not enforced, allow traffic
            desc->action = DP_POLICY_ACTION_ALLOW;
        }
    } else {
        //for traffic between 2 EPs in same domain that enabled
        //namespace boundary enoforcement, we need to mark NBE flag
        if (p->ep->nbe) {
            if (is_ingress) {
                bool is_internal = dpi_is_ip4_internal(sip);

                if (is_internal && !(hdl->apply_dir & DP_POLICY_APPLY_INGRESS)) {
                    if (desc->action == DP_POLICY_ACTION_DENY) {
                        desc->flags |= POLICY_DESC_NBE_SNS;
                    }
                }
            } else {
                int is_internal = dpi_is_ip4_internal(dip);
                if (is_internal && !(hdl->apply_dir & DP_POLICY_APPLY_EGRESS)) {
                    if (desc->action == DP_POLICY_ACTION_DENY) {
                        desc->flags |= POLICY_DESC_NBE_SNS;
                    }
                }
            }
        }
    }
}

static bool _dpi_policy_implicit_default(dpi_policy_hdl_t *hdl, dpi_policy_desc_t *desc)
{
    if (hdl == NULL || desc == NULL) {
        return false;
    }
    if ( desc->order == 0xffffffff && desc->id == 0
        && (desc->flags & POLICY_DESC_CHECK_VER)
        && desc->action == hdl->def_action
        && (desc->action == DP_POLICY_ACTION_VIOLATE
        || desc->action == DP_POLICY_ACTION_DENY) ) {
        return true;
    }
    return false;
}

static void _dpi_policy_chk_unknown_ip(dpi_policy_hdl_t *hdl, uint32_t sip, uint32_t dip,
                                    uint8_t iptype, dpi_policy_desc_t **pol_desc)
{
    if (hdl == NULL || pol_desc == NULL) return;

    dpi_policy_desc_t *desc = *pol_desc;
    dpi_unknown_ip_desc_t uip_desc;
    bool is_external = false;
    if (desc->flags & POLICY_DESC_EXTERNAL) {
        is_external = true;
    }

    //unknown ip desc
    memset(&uip_desc, 0, sizeof(uip_desc));
    uip_desc.sip = sip;
    uip_desc.dip = dip;

    if (iptype == DP_IPTYPE_NONE ||
        iptype == DP_IPTYPE_HOSTIP ||
        iptype == DP_IPTYPE_TUNNELIP) {//unknown wl
        uint16_t thdl_ver = hdl?hdl->ver:0;
        dpi_unknown_ip_cache_t *uip_cache = rcu_map_lookup(&th_unknown_ip_map, &uip_desc);
        if (uip_cache != NULL) {
            if (thdl_ver == uip_cache->desc.hdl_ver &&
                th_snap.tick - uip_cache->start_hit < POLICY_DESC_VER_CHG_MAX) {
                desc->flags &= ~(POLICY_DESC_CHECK_VER);
                desc->flags |= POLICY_DESC_UNKNOWN_IP;
                desc->flags |= POLICY_DESC_TMP_OPEN;
                desc->action = DP_POLICY_ACTION_OPEN;
                update_unknown_ip_cache(uip_cache);
            } else {
                //try above condition UNKNOWN_IP_TRY_COUNT time
                uint8_t try_cnt = uip_cache->try_cnt;
                if (try_cnt > 0) {
                    try_cnt--;
                    refresh_unknown_ip_cache(uip_cache, thdl_ver, try_cnt);
                    desc->flags &= ~(POLICY_DESC_CHECK_VER);
                    desc->flags |= POLICY_DESC_UNKNOWN_IP;
                    desc->flags |= POLICY_DESC_TMP_OPEN;
                    desc->action = DP_POLICY_ACTION_OPEN;
                }
            }
        } else {
            uip_desc.hdl_ver = thdl_ver;
            add_unknown_ip_cache(&uip_desc, &uip_desc, iptype, is_external);
            desc->flags &= ~(POLICY_DESC_CHECK_VER);
            desc->flags |= POLICY_DESC_UNKNOWN_IP;
            desc->flags |= POLICY_DESC_TMP_OPEN;
            desc->action = DP_POLICY_ACTION_OPEN;
        }
    } else if (iptype == DP_IPTYPE_DEVIP) {
        //connection from nv device is open
        desc->flags &= ~(POLICY_DESC_CHECK_VER);
        desc->flags |= POLICY_DESC_TMP_OPEN;
        desc->action = DP_POLICY_ACTION_OPEN;
    }
}

static int _dpi_policy_lookup_by_key(dpi_policy_hdl_t *hdl, dpi_rule_key_t *key,
                                     int is_ingress, dpi_policy_desc_t *desc)
{
    dpi_rule_t *r;
    r = rcu_map_lookup(&hdl->policy_map, key);
    if (r) {
        policy_desc_cpy(desc, &r->desc);
        goto exit;
    } else {
        dpi_range_rule_key_t key2;
        dpi_range_rule_t *r2;
        dpi_range_rule_item_t *item;

        memset(&key2, 0, sizeof(key2));
        key2.proto = key->proto;
        if (is_ingress) {
            key2.flag = DP_RANGE_RULE_INGRESS;
            key2.ip = key->dip;
        } else {
            key2.flag = DP_RANGE_RULE_EGRESS;
            key2.ip = key->sip;
        }
        r2 = rcu_map_lookup(&hdl->range_policy_map, &key2);
        if (r2) {
            item = dpi_range_rule_match(r2, key);
            if (item) {
                policy_desc_cpy(desc, &item->desc);
                goto exit;
            }
        }

        /* match no direction rule */
        key2.flag = 0;
        key2.ip = 0;
        r2 = rcu_map_lookup(&hdl->range_policy_map, &key2);
        if (r2) {
            item = dpi_range_rule_match(r2, key);
            if (item) {
                policy_desc_cpy(desc, &item->desc);
                goto exit;
            }
        }
        /* match not found */
        desc->id = 0;
        desc->action = hdl->def_action;
        desc->flags = POLICY_DESC_CHECK_VER;
        desc->order = 0xffffffff;
        desc->hdl_ver = 0;
    }
exit:
    DEBUG_POLICY(" key:" DP_RULE_STR "match: " DP_POLICY_DESC_STR "\n",
                 DP_RULE_KEY(key), DP_POLICY_DESC(desc));
    return 0;
}

static bool _dpi_is_chk_nbe(dpi_packet_t *p)
{
    if (!p || !p->ep) {
        return false;
    }
    if (p->ep->nbe) {
        return true;
    }
    return false;
}

#define policy_desc_merge(desc1, desc2) \
    if ((desc2)->id > 0 && (desc2)->order < (desc1)->order) { \
        memcpy((desc1), (desc2), sizeof(dpi_policy_desc_t)); \
    }

static int dpi_policy_lookup_by_key(dpi_policy_hdl_t *hdl, uint32_t sip, uint32_t dip,
                                    uint16_t dport, uint16_t proto, uint32_t app,
                                    int is_ingress, dpi_policy_desc_t *desc, dpi_packet_t *p)
{
    dpi_rule_key_t key;
    bool is_nbe = _dpi_is_chk_nbe(p);

    if (unlikely(!hdl || th_disable_net_policy)) {
        // workload just created, allow traffic pass until policy being configured
        desc->id = 0;
        desc->action = DP_POLICY_ACTION_OPEN;
        desc->flags = POLICY_DESC_CHECK_VER;
        desc->flags |= POLICY_DESC_TMP_OPEN;
        if (is_ingress) {
            desc->flags |= dpi_is_ip4_internal(sip)?
                               POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
        } else {
            desc->flags |= dpi_is_ip4_internal(dip)?
                               POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
        }
        goto exit;
    }
    if (IS_IN_LINKLOCAL(ntohl(sip)) || IS_IN_LINKLOCAL(ntohl(dip))) {
        // cilium use link_local ip as service loopback
        desc->id = 0;
        desc->action = DP_POLICY_ACTION_OPEN;
        desc->flags = POLICY_DESC_CHECK_VER;
        desc->flags |= POLICY_DESC_INTERNAL;
        desc->flags |= POLICY_DESC_LINK_LOCAL;
        goto exit;
    }
    memset(&key, 0, sizeof(key));
    key.sip = sip;
    key.dip = dip;
    key.dport= dport;
    key.proto = proto;
    key.app = app;

    if (is_ingress) {
        bool is_internal = dpi_is_ip4_internal(key.sip);
        uint8_t iptype = dpi_ip4_iptype(key.sip);

        if (is_internal && !(hdl->apply_dir & DP_POLICY_APPLY_INGRESS) &&
            iptype != DP_IPTYPE_UWLIP && !is_nbe) {
            // east-west ingress traffic is always allowed
            desc->id = 0;
            desc->action = DP_POLICY_ACTION_OPEN;
            desc->flags = POLICY_DESC_INTERNAL;
            //on openshift platform, we mark it
            //if ingress traffic is from tunnel ip
            if (iptype == DP_IPTYPE_TUNNELIP) {
                desc->flags |= POLICY_DESC_TUNNEL;
            } else if (iptype == DP_IPTYPE_HOSTIP) {
                desc->flags |= POLICY_DESC_HOSTIP;
            }
        } else {
            if (iptype == DP_IPTYPE_UWLIP && !th_detect_unmanaged_wl) {
                // traffic from unmanaged workload is not enforced,
                // therefore  east-west ingress traffic is allowed
                desc->id = 0;
                desc->action = DP_POLICY_ACTION_OPEN;
                desc->flags = is_internal ? POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
                goto exit;
            }
            dpi_policy_desc_t desc2;
            _dpi_policy_lookup_by_key(hdl, &key, is_ingress, desc);

            // traffic can match fqdn or external rule or address
            // group rule, so do multiple lookup here
            if (DPI_POLICY_HAS_FQDN(hdl)) {
                int rt = 0;
                /*
                 * A FQDN can have exact match (eg. mail.yahoo.com)
                 * or wildcard match (eg. *.yahoo.com), so we need
                 * to do policy match for all these cases and merge
                 * final match results.
                 */
                rt = policy_match_ipv4_fqdn_code(g_fqdn_hdl, sip, hdl, &key, is_ingress, &desc2, p);
                if (rt > 0) {
                    policy_desc_merge(desc, &desc2);
                }
            }

            if (!is_internal) {
                key.sip = 0;
                _dpi_policy_lookup_by_key(hdl, &key, is_ingress, &desc2);
                policy_desc_merge(desc, &desc2);
                desc->flags |= POLICY_DESC_EXTERNAL;
            } else {
                desc->flags |= POLICY_DESC_INTERNAL;
            }
        }
    } else {
        int is_internal = dpi_is_ip4_internal(key.dip);
        uint8_t iptype = dpi_ip4_iptype(key.dip);
        fqdn_ipv4_entry_t *ipv4_ent = NULL;
        ipv4_ent = rcu_map_lookup(&g_fqdn_hdl->fqdn_ipv4_map, &(key.dip));
        bool is_src_internal = dpi_is_ip4_internal(key.sip);

        //NVSHAS-8989, we see only partial packets from long session
        //which could cause session direction be mistaken in openshift,
        //then this can cause false alert, we need to let such special
        //passthrough packet from external to bypass policy match in the
        //intermediate container, the policy match need to be done at the
        //source/destination container
        if (is_internal && !is_src_internal && (hdl->apply_dir & DP_POLICY_APPLY_EGRESS)) {
            desc->id = 0;
            desc->action = DP_POLICY_ACTION_OPEN;
            desc->flags = POLICY_DESC_INTERNAL;
            goto exit;
        }
        //client inside cluster connect to server service
        //with type externalIP has MITM (man in the middle)
        //risk, implicitly warn/block it
        if (!is_internal && iptype == DP_IPTYPE_EXTIP) {
            desc->id = 0;
            if (hdl->def_action == DP_POLICY_ACTION_DENY) {
                desc->action = DP_POLICY_ACTION_DENY;
            } else {
                desc->action = DP_POLICY_ACTION_VIOLATE;
            }
            desc->flags |= POLICY_DESC_EXTERNAL;
            desc->flags |= POLICY_DESC_SVC_EXTIP;
            desc->order = 0xffffffff;
            goto exit;
        }
        //on k8s platform, we want to learn policy if
        //egress traffic is to host ip
        if (is_internal && !(hdl->apply_dir & DP_POLICY_APPLY_EGRESS) && !ipv4_ent &&
            iptype != DP_IPTYPE_HOSTIP && iptype != DP_IPTYPE_UWLIP && !is_nbe) {
            // east-west egress traffic is always allowed
            desc->id = 0;
            desc->action = DP_POLICY_ACTION_OPEN;
            desc->flags = POLICY_DESC_INTERNAL;
        } else {
            if (iptype == DP_IPTYPE_UWLIP && !th_detect_unmanaged_wl) {
                // traffic to unmanaged workload is not enforced,
                // therefore  east-west egress traffic is allowed
                desc->id = 0;
                desc->action = DP_POLICY_ACTION_OPEN;
                desc->flags = is_internal ? POLICY_DESC_INTERNAL:POLICY_DESC_EXTERNAL;
                goto exit;
            }
            if (is_nbe && iptype == DP_IPTYPE_SVCIP) {
                //no check for cross namespace for svc ip traffic
                desc->id = 0;
                desc->action = DP_POLICY_ACTION_OPEN;
                desc->flags = POLICY_DESC_INTERNAL;
                goto exit;
            }
            dpi_policy_desc_t desc2;
            _dpi_policy_lookup_by_key(hdl, &key, is_ingress, desc);

            if (DPI_POLICY_HAS_FQDN(hdl)) {
                int rt = 0;
                /*
                 * A FQDN can have exact match (eg. mail.yahoo.com)
                 * or wildcard match (eg. *.yahoo.com), so we need 
                 * to do policy match for all these cases and merge
                 * final match results(dpi_policy_desc_t)
                 */
                rt = policy_match_ipv4_fqdn_code(g_fqdn_hdl, dip, hdl, &key, is_ingress, &desc2, p);
                if (rt > 0) {
                    policy_desc_merge(desc, &desc2);
                }
            }

            if (!is_internal) {
                key.dip = 0;
                _dpi_policy_lookup_by_key(hdl, &key, is_ingress, &desc2);
                policy_desc_merge(desc, &desc2);
                desc->flags |= POLICY_DESC_EXTERNAL;
            } else {
                desc->flags |= POLICY_DESC_INTERNAL;
            }
        }
    }
exit:
    desc->hdl_ver = hdl?hdl->ver:0;
    return 0;
}

static void * get_parent_policy_hdl(struct ether_addr *pmac)
{
    io_ep_t *pep;
    void *pbuf;
    if (!mac_zero(pmac->ether_addr_octet)) {
        pbuf = rcu_map_lookup(&g_ep_map, pmac);
        if (pbuf) {
            pep = GET_EP_FROM_MAC_MAP(pbuf);
            if (pep) {
                return pep->policy_hdl;
            }
        }
    }
    return NULL;
}

// Packet reeval returns 1 if action changes and is violate or deny (thus need to log)
// It also mark pkt to log if action or matched rule id changes (in either direction)
// caller make sure that the session is not NULL
int dpi_policy_reeval(dpi_packet_t *p, bool to_server)
{
    int policy_eval = 0;
    dpi_session_t *s = p->session;
    int log_violate = 0;
    uint8_t old_action = s->policy_desc.action;
    uint32_t old_rule_id = s->policy_desc.id;
    dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)p->ep->policy_hdl;
    bool xff = false;
    uint8_t old_xff_action = s->xff_desc.action;
    uint32_t old_xff_rule_id = s->xff_desc.id;

    if (unlikely((s->policy_desc.hdl_ver != p->ep->policy_ver) &&
        (s->policy_desc.flags & POLICY_DESC_UNKNOWN_IP))) {
        dpi_policy_lookup(p, hdl, 0, to_server, xff, &s->policy_desc, 0);
        policy_eval = 1;
    }

    if (unlikely((s->policy_desc.hdl_ver != p->ep->policy_ver) &&
        (s->policy_desc.flags & POLICY_DESC_CHECK_VER))) {
        dpi_policy_lookup(p, hdl, 0, to_server, xff, &s->policy_desc, 0);
        policy_eval = 1;
    }

    if (unlikely((s->policy_desc.action == DP_POLICY_ACTION_CHECK_VH) &&
        FLAGS_TEST(s->flags, DPI_SESS_FLAG_POLICY_APP_READY))) {
        dpi_policy_lookup(p, hdl, 0, to_server, xff, &s->policy_desc, 0);
        policy_eval = 1;
    }

    if (unlikely((s->policy_desc.action == DP_POLICY_ACTION_CHECK_APP) &&
        FLAGS_TEST(s->flags, DPI_SESS_FLAG_POLICY_APP_READY))) {
        uint32_t app = s->app?s->app:(s->base_app?s->base_app:DP_POLICY_APP_UNKNOWN);
        //for midstream session if app is unknown, skip policy match
        if (app != DP_POLICY_APP_UNKNOWN || !FLAGS_TEST(s->flags, DPI_SESS_FLAG_MID_STREAM)) {
            //use 0xffffffff to indicate app cannot be identified
            dpi_policy_lookup(p, hdl, app, to_server, xff, &s->policy_desc, 0);
            policy_eval = 1;
        }
    }

    //this is for istio, return packet from svr shows correct svr ip
    //instead of 127.0.0.1, so we do a meaningful policy match
    if(unlikely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_MESH_TO_SVR))) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        if ((iph->saddr == iph->daddr) ||
            iph->daddr == htonl(INADDR_LOOPBACK) || IS_IN_LOOPBACK(ntohl(iph->daddr)) ||
            iph->saddr == htonl(INADDR_LOOPBACK) || IS_IN_LOOPBACK(ntohl(iph->saddr))) {
        } else {
            bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);
            dpi_policy_hdl_t *phdl;
            if (isproxymesh && p->ep) {
                phdl = (dpi_policy_hdl_t *)get_parent_policy_hdl(&p->ep->pmac);
                DEBUG_POLICY("MESH_TO_SVR switch policy hdl(%p) to proxymesh parent hdl(%p)\n",hdl, phdl);
                hdl = phdl;
                dpi_policy_lookup(p, hdl, 0, to_server, xff, &s->policy_desc, 0);
                if (unlikely((s->policy_desc.action == DP_POLICY_ACTION_CHECK_APP) &&
                    FLAGS_TEST(s->flags, DPI_SESS_FLAG_POLICY_APP_READY))) {
                    uint32_t app = s->app?s->app:(s->base_app?s->base_app:DP_POLICY_APP_UNKNOWN);
                    if (app != DP_POLICY_APP_UNKNOWN || !FLAGS_TEST(s->flags, DPI_SESS_FLAG_MID_STREAM)) {
                        dpi_policy_lookup(p, hdl, app, to_server, xff, &s->policy_desc, 0);
                    }
                }
                s->policy_desc.flags &= ~(POLICY_DESC_CHECK_VER);
                s->policy_desc.flags |= POLICY_DESC_MESH_TO_SVR;
                policy_eval = 1;
            }
        }
    }

    //use original client ip saved in X-Forwarded-For header to match policy
    //this is used to detect traffic from router/ingress via loadbalancer
    if(unlikely(th_xff_enabled && FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS) &&
        FLAGS_TEST(s->flags, DPI_SESS_FLAG_XFF))) {
        //for proxymesh traffic monitored from 'lo' i/f, policy match for
        //XFF traffic needs to be done on proxymesh's original mac
        struct iphdr *iph;
        uint32_t dip;
        bool dstlo = false;
        bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);
        dpi_policy_hdl_t *phdl;
        if (isproxymesh && p->ep) {
            phdl = (dpi_policy_hdl_t *)get_parent_policy_hdl(&p->ep->pmac);
            DEBUG_POLICY("XFF switch policy hdl(%p) to proxymesh parent hdl(%p)\n",hdl, phdl);
            hdl = phdl;
            //check whether dst ip is 127.0.0.x
            iph = (struct iphdr *)(p->pkt + p->l3);
            dip = to_server?iph->daddr:iph->saddr;
            dstlo = IS_IN_LOOPBACK(ntohl(dip));
        }
        xff = true;
        if (s->xff_app == 0) {
            //no X-Forwarded-Proto in header
            s->xff_app = s->app?s->app:(s->base_app?s->base_app:DP_POLICY_APP_UNKNOWN);
        }
        if (dstlo) {
            //in service mesh's case, if dst ip is lo ip we need to
            //use its parent container's ip to replace dst ip for policy
            //match, most container has just 1 IP, technically it can have
            //more, once we see violation we break out loop
            int idx;
            if (p->ep && p->ep->pips) {
                for (idx = 0; idx < p->ep->pips->count; idx++) {
                    dpi_policy_lookup(p, hdl, 0, to_server, xff, &s->xff_desc, p->ep->pips->list[idx].ip);
                    if (unlikely((s->xff_desc.action == DP_POLICY_ACTION_CHECK_APP))) {
                        dpi_policy_lookup(p, hdl, s->xff_app, to_server, xff, &s->xff_desc, p->ep->pips->list[idx].ip);
                    }
                    if (DPI_POLICY_LOG_VIOLATE(s->xff_desc.action)) {
                        break;
                    }
                }
            }
        } else {
            dpi_policy_lookup(p, hdl, 0, to_server, xff, &s->xff_desc, 0);
            if (unlikely((s->xff_desc.action == DP_POLICY_ACTION_CHECK_APP))) {
                dpi_policy_lookup(p, hdl, s->xff_app, to_server, xff, &s->xff_desc, 0);
            }
        }
        policy_eval = 1;
    }

    if (policy_eval) {
        if (xff) {
            bool chg = false;
            log_violate = DPI_POLICY_LOG_VIOLATE(s->policy_desc.action);
            log_violate += DPI_POLICY_LOG_VIOLATE(s->xff_desc.action);
            if ((old_xff_action != s->xff_desc.action) ||
                (old_xff_rule_id != s->xff_desc.id)) {
                FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_XFF);
                chg = true;
            }
            if ((old_action != s->policy_desc.action) ||
                (old_rule_id != s->policy_desc.id)) {
                // Force log if action changed after reeval
                FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_MID);
                chg = true;
            }
            if (!chg) {
                // No action change after reeval, no need to log
                log_violate = 0;
            }
        } else {
            log_violate = DPI_POLICY_LOG_VIOLATE(s->policy_desc.action);
            if ((old_action != s->policy_desc.action) ||
                (old_rule_id != s->policy_desc.id)) {
                // Force log if action changed after reeval
                FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_MID);
            } else {
                // No action change after reeval, no need to log
                log_violate = 0;
            }
        }
    }
    return log_violate;
}

// Session reeval returns 1 if action changes and is violate or deny
int dpi_sess_policy_reeval(dpi_session_t *s)
{
    int policy_eval = 0;
    uint32_t sip, dip;
    uint16_t dport, proto;
    int is_ingress;
    void *buf;
    uint8_t *ep_mac;
    io_ep_t *ep;
    uint32_t app = 0;
    int log_violate = 0;
    uint8_t old_action = s->policy_desc.action;
    uint32_t old_rule_id = s->policy_desc.id;
    dpi_policy_hdl_t *hdl;

    if (!(s->policy_desc.flags & POLICY_DESC_CHECK_VER)) {
        return 0;
    }

    is_ingress = (s->flags & DPI_SESS_FLAG_INGRESS);
    ep_mac = is_ingress?s->server.mac:s->client.mac;
    buf = rcu_map_lookup(&g_ep_map, ep_mac);
    if (!buf) {
        DEBUG_POLICY("cannot find mac: "DBG_MAC_FORMAT "\n", DBG_MAC_TUPLE(ep_mac));
        return 0;
    }
    ep = GET_EP_FROM_MAC_MAP(buf);

    sip = s->client.ip.ip4;
    dip = s->server.ip.ip4;
    dport = s->server.port;
    proto = s->ip_proto;
    hdl = (dpi_policy_hdl_t *)ep->policy_hdl;

    if (unlikely((s->policy_desc.hdl_ver != ep->policy_ver) &&
        (s->policy_desc.flags & POLICY_DESC_CHECK_VER))) {
        dpi_policy_lookup_by_key(hdl, sip, dip, dport,
                                 proto, 0, is_ingress, &s->policy_desc, NULL);
        policy_eval = 1;
    }

    if (unlikely((s->policy_desc.action == DP_POLICY_ACTION_CHECK_APP) &&
        FLAGS_TEST(s->flags, DPI_SESS_FLAG_POLICY_APP_READY))) {
        app = s->app?s->app:(s->base_app?s->base_app:DP_POLICY_APP_UNKNOWN);
        //use 0xffffffff to indicate app cannot be identified
        dpi_policy_lookup_by_key(hdl, sip, dip, dport,
                                 proto, app, is_ingress, &s->policy_desc, NULL);
        policy_eval = 1;
    }

    if (policy_eval) {
        DEBUG_POLICY("hdl %p sip %x dip %x dport %u proto %u"
                     " app %u ingress %d\n",
                     ep->policy_hdl, sip, dip, dport, proto, app, is_ingress);
        if (DPI_POLICY_LOG_VIOLATE(s->policy_desc.action) &&
            ((old_action != s->policy_desc.action) ||
             (old_rule_id != s->policy_desc.id))) {
            log_violate = 1;
        }
    }

    return log_violate;
}

/*-----------------------------------------------------------*
 *------------- Policy config -------------------------------*
 *-----------------------------------------------------------*/
static uint16_t policy_ver = 0;
#define GET_NEW_POLICY_VER()  ((++policy_ver)?policy_ver:(++policy_ver))

/*
static void dpi_policy_set_session_reeval()
{
    struct cds_lfht_node *node;
    struct cds_lfht_iter iter;
    uint16_t new_policy_ver = GET_NEW_POLICY_VER();
    RCU_MAP_ITR_FOR_EACH(&g_ep_map, iter, node) {
        io_mac_t *mac = STRUCT_OF(node, io_mac_t, node);
        if (mac->broadcast || mac->unicast) continue;
        io_ep_t *ep = mac->ep;
        if (ep->policy_hdl) {
            ep->policy_ver = new_policy_ver;
            ((dpi_policy_hdl_t *)ep->policy_hdl)->ver = ep->policy_ver;
        }
    }
    DEBUG_POLICY("new policy ver: %d\n", new_policy_ver);
}
*/

int dpi_policy_update(struct ether_addr *mac_addr, dpi_policy_hdl_t *hdl)
{
    void *buf;
    io_ep_t *ep;
    dpi_policy_hdl_t *old;

    if (!mac_addr) {
        return -1;
    }
    rcu_read_lock();
    buf = rcu_map_lookup(&g_ep_map, mac_addr);
    if (!buf) {
        rcu_read_unlock();
        DEBUG_POLICY("cannot find mac: "DBG_MAC_FORMAT "\n", DBG_MAC_TUPLE(*mac_addr));
        return -1;
    }
    ep = GET_EP_FROM_MAC_MAP(buf);

    old = (dpi_policy_hdl_t *)ep->policy_hdl;
    if (hdl) {
        hdl->ref_cnt++;
    }
    ep->policy_hdl = (void *)hdl;
    ep->policy_ver = hdl?hdl->ver:0;
    rcu_read_unlock();

    if (old) {
        if (old->ref_cnt < 2) {
            synchronize_rcu();
        }
        dpi_policy_hdl_destroy(old);
    }
    DEBUG_POLICY("mac: "DBG_MAC_FORMAT" policy hdl %p ver %u done\n",
               DBG_MAC_TUPLE(*mac_addr), hdl, ep->policy_ver);
    return 0;
}

int dpi_policy_cfg(int cmd, dpi_policy_t *p, int flag)
{
    int i;
    static dpi_policy_hdl_t *hdl = NULL;
    static uint32_t order = 0;
    DEBUG_POLICY("cmd %d, num_macs: %d, num_rules %d flag 0x%x\n",
               cmd, p->num_macs, p->num_rules, flag);

    if (flag & MSG_START) {
       if (hdl) {
           DEBUG_ERROR(DBG_POLICY, "old policy hdl %p exists!\n", hdl);
           dpi_policy_hdl_destroy(hdl);
           hdl = NULL;
       }
    } else {
        if (!hdl) {
            DEBUG_ERROR(DBG_POLICY, "missed msg start!\n");
            return -1;
        }
    }

    if (cmd != CFG_DELETE) {
        if (flag & MSG_START) {
            hdl = dpi_policy_hdl_init(p->def_action);
            hdl->apply_dir = p->apply_dir;
            order = 0;
            if (!hdl) {
                return -1;
            }
            hdl->ver = GET_NEW_POLICY_VER();
        }
        for (i = 0; i < p->num_rules; i++) {
            dpi_rule_key_t key;
            dpi_policy_desc_t desc;
            int dir;
            memset(&key, 0, sizeof(key));
            memset(&desc, 0, sizeof(desc));

            if (p->rule_list[i].fqdn[0] != '\0') {
               uint32_t code;
               if (p->rule_list[i].ingress) {
                   rcu_read_lock();
                   code = config_fqdn_ipv4_mapping(g_fqdn_hdl,
                            p->rule_list[i].fqdn, p->rule_list[i].sip, p->rule_list[i].vh);
                   rcu_read_unlock();
                   if (code == -1) {
                       continue;
                   }
                   p->rule_list[i].sip = code;
                   p->rule_list[i].sip_r = code;
               } else {
                   rcu_read_lock();
                   code = config_fqdn_ipv4_mapping(g_fqdn_hdl,
                            p->rule_list[i].fqdn, p->rule_list[i].dip, p->rule_list[i].vh);
                   rcu_read_unlock();
                   if (code == -1) {
                       continue;
                   }
                   p->rule_list[i].dip = code;
                   p->rule_list[i].dip_r = code;
               }
               hdl->flag |= POLICY_HDL_FLAG_FQDN;
            }

            key.sip = p->rule_list[i].sip;
            key.dip = p->rule_list[i].dip;
            key.dport = p->rule_list[i].dport;
            key.proto =  p->rule_list[i].proto;
            desc.id = p->rule_list[i].id;
            desc.action = p->rule_list[i].action;
            desc.flags = POLICY_DESC_CHECK_VER;
            desc.order = ++order;
            dir = p->rule_list[i].ingress?POLICY_RULE_DIR_INGRESS:POLICY_RULE_DIR_EGRESS;

            if (key.dport != p->rule_list[i].dport_r || key.sip != p->rule_list[i].sip_r ||
                    key.dip != p->rule_list[i].dip_r) {
                dpi_rule_key_t key_r;
                memcpy(&key_r, &key, sizeof(dpi_rule_key_t));
                key_r.dport = p->rule_list[i].dport_r;
                key_r.sip = p->rule_list[i].sip_r;
                key_r.dip = p->rule_list[i].dip_r;
                if (key.proto > 0) {
                    dpi_rule_add(hdl, &key, &key_r,
                                 p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                 dir, &desc);
                } else {
                    key.proto = key_r.proto = IPPROTO_TCP;
                    dpi_rule_add(hdl, &key, &key_r,
                                 p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                 dir, &desc);
                    key.proto = key_r.proto = IPPROTO_UDP;
                    dpi_rule_add(hdl, &key, &key_r,
                                 p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                 dir, &desc);
                    if (g_enable_icmp_policy) {
                        key.proto = key_r.proto = IPPROTO_ICMP;
                        dpi_rule_add(hdl, &key, &key_r,
                                    p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                    dir, &desc);
                    }
                }
            } else {
                if (key.proto > 0) {
                    dpi_rule_add(hdl, &key, NULL,
                                 p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                 dir, &desc);
                } else {
                    key.proto = IPPROTO_TCP;
                    dpi_rule_add(hdl, &key, NULL,
                                 p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                 dir, &desc);
                    key.proto = IPPROTO_UDP;
                    dpi_rule_add(hdl, &key, NULL,
                                 p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                 dir, &desc);
                    if (g_enable_icmp_policy) {
                        key.proto = IPPROTO_ICMP;
                        dpi_rule_add(hdl, &key, NULL,
                                    p->rule_list[i].num_apps,p->rule_list[i].app_rules,
                                    dir, &desc);
                    }
                }
            }
        }
        if (flag & MSG_END) {
            if (!g_enable_icmp_policy) {
                dpi_add_default_policy(hdl);
            }
        }
    } else {
        if (hdl != NULL) {
            DEBUG_POLICY("old policy hdl %p exists while receiving delete\n", hdl);
            dpi_policy_hdl_destroy(hdl);
            hdl = NULL;
            order = 0;
        }
    }

    if (!(flag & MSG_END)) {
        return 0;
    }

    for (i = 0; i < p->num_macs; i++) {
        dpi_policy_update(&p->mac_list[i], hdl);
    }
    if (hdl && hdl->ref_cnt == 0) {
        dpi_policy_hdl_destroy(hdl);
    }

    hdl = NULL;
    return 0;
}

void dp_policy_destroy(void *policy_hdl)
{
    if (policy_hdl) {
        dpi_policy_hdl_destroy((dpi_policy_hdl_t *)policy_hdl);
    }
}

/*
 *--------------------------------------------------------
 *---fqdn handling---------------------------------------
 *-------------------------------------------------------
 */
static int fqdn_name_match(struct cds_lfht_node *ht_node, const void *key)
{
    fqdn_name_entry_t *s = STRUCT_OF(ht_node, fqdn_name_entry_t, node);
    const char *k = key;
    return strcasecmp(s->r->name, k)?0:1;
}

static uint32_t fqdn_name_hash(const void *key)
{
    //key is null terminated
    const char *k = key;
    return sdbm_hash((uint8_t *)k, strlen(k)*sizeof(char));
}

static int fqdn_ipv4_match(struct cds_lfht_node *ht_node, const void *key)
{
    fqdn_ipv4_entry_t *s = STRUCT_OF(ht_node, fqdn_ipv4_entry_t, node);
    const uint32_t *k = key;
    return (s->ip == *k);
}

static uint32_t fqdn_ipv4_hash(const void *key)
{
    const uint32_t *k = key;
    return sdbm_hash((uint8_t *)k, sizeof(uint32_t));
}

static dpi_fqdn_hdl_t *dpi_fqdn_hdl_init()
{
    dpi_fqdn_hdl_t *hdl;
    hdl = calloc(sizeof(dpi_fqdn_hdl_t), 1);
    if (!hdl) {
        DEBUG_ERROR(DBG_POLICY, "Out of memory!");
        return NULL;
    }

    DEBUG_POLICY("%p\n", hdl);
    hdl->bm = bitmap_allocate(DPI_FQDN_MAX_ENTRIES);
    if (!hdl->bm) {
        DEBUG_ERROR(DBG_POLICY, "Out of memory!");
        free(hdl);
        return NULL;
    }
    rcu_map_init(&(hdl->fqdn_name_map), 32, offsetof(fqdn_name_entry_t, node),
                 fqdn_name_match, fqdn_name_hash);
    rcu_map_init(&(hdl->fqdn_ipv4_map), 32, offsetof(fqdn_ipv4_entry_t, node),
                 fqdn_ipv4_match, fqdn_ipv4_hash);
    CDS_INIT_LIST_HEAD(&hdl->del_rlist);
    return hdl;
}

static uint32_t alloc_fqdn_code(dpi_fqdn_hdl_t *hdl)
{
    hdl->code_cnt = bitmap_get_next_zero(hdl->bm, hdl->code_cnt);
    if (hdl->code_cnt < 0) {
        DEBUG_ERROR(DBG_POLICY, "used up fqdn code!!\n");
        return -1;
    }
    bitmap_set(hdl->bm, hdl->code_cnt);
    hdl->code_cnt++;
    return htonl(hdl->code_cnt);
}

static void free_fqdn_code(dpi_fqdn_hdl_t *hdl, uint32_t code)
{
    bitmap_clear(hdl->bm, ntohl(code)-1);
    return;
}

static bool is_fqdn_name_wildcard(char* name)
{
    int count;
    char **tokens;

    if (name == NULL) {
        return false;
    }

    tokens = str_split(name, ".", &count);
    if (tokens == NULL) {
        return false;
    }

    if ((count > 0) && (strcasecmp(tokens[0], "*") == 0)){
        free_split(tokens, count);
        return true;
    }
    free_split(tokens, count);
    return false;
}

//caller make sure entry and r is not NULL
static void config_fqdn_init_ip_record_list(fqdn_ipv4_entry_t *ipv4_entry, fqdn_record_t *r)
{
    if(ipv4_entry->rlist.prev==NULL && ipv4_entry->rlist.next==NULL) {
        CDS_INIT_LIST_HEAD(&ipv4_entry->rlist);
    }
    if(r->iplist.prev==NULL && r->iplist.next==NULL) {
        CDS_INIT_LIST_HEAD(&r->iplist);
    }
}

//caller make sure entry and r is not NULL
static bool find_record_or_ipentry(fqdn_ipv4_entry_t *entry, fqdn_record_t *r, bool recordInIp)
{
    if (recordInIp) {
        fqdn_record_item_t *r_itr, *r_next;
        cds_list_for_each_entry_safe(r_itr, r_next, &entry->rlist, node) {
            if (r_itr->r == r) {
                return true;
            }
        }
        return false;
    } else {
        fqdn_ipv4_item_t *ipv4_itr, *ipv4_next;
        cds_list_for_each_entry_safe(ipv4_itr, ipv4_next, &r->iplist, node) {
            if (ipv4_itr->ip == entry->ip) {
                return true;
            }
        }
        return false;
    }
}

//caller make sure entry and r is not NULL
static int config_record_ip_list(fqdn_ipv4_entry_t *entry, fqdn_record_t *r)
{
    if (!entry || !r){
        return -1;
    }
    fqdn_record_item_t *record_item;
    fqdn_ipv4_item_t *ipv4_item;
    //init list
    config_fqdn_init_ip_record_list(entry,r);
    //one ip can map to multiple fqdn record
    record_item = calloc(1, sizeof(fqdn_record_item_t));
    if (record_item == NULL) {
        DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
        return -1;
    }
    //one fqdn record can map to multiple ip
    ipv4_item = calloc(1, sizeof(fqdn_ipv4_item_t));
    if (ipv4_item == NULL) {
        DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
        free(record_item);
        return -1;
    }
    if (!find_record_or_ipentry(entry, r, true)){
        //add record_item to ipv4_entry's record list
        record_item->r = r;
        cds_list_add_tail((struct cds_list_head *)record_item, &entry->rlist);
        //DEBUG_POLICY("add record(%p) code(0x%08x) to ipv4_entry's rlist\n", record_item->r, record_item->r->code);
    } else {
        free(record_item);
    }
    if (!find_record_or_ipentry(entry, r, false)) {
        //add ipv4_item to fqdn_record's iplist
        ipv4_item->ip = entry->ip;
        cds_list_add_tail((struct cds_list_head *)ipv4_item, &r->iplist);
        r->ip_cnt++;
        //DEBUG_POLICY("add ip(0x%08x) to record(%p)code(0x%08x)'s iplist, ipcnt(%u)\n", ipv4_item->ip, r, r->code, r->ip_cnt);
        //return 1 means this ip may need to be sent to consul
        return 1;
    } else {
        free(ipv4_item);
    }
    return 0;
}

// Called by policy config (ctrl)
uint32_t config_fqdn_ipv4_mapping(dpi_fqdn_hdl_t *hdl, char *name, uint32_t ip, bool vh)
{
    fqdn_name_entry_t *name_entry;
    fqdn_ipv4_entry_t *ipv4_entry;
    fqdn_record_t *r = NULL;

    name_entry = rcu_map_lookup(&hdl->fqdn_name_map, name);
    if (!name_entry) {
        fqdn_name_entry_t *entry;
        entry  = (fqdn_name_entry_t *)calloc(1, sizeof(fqdn_name_entry_t));
        if (!entry) {
            DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
            return -1;
        }

        r = (fqdn_record_t *)calloc(1, sizeof(fqdn_record_t));
        if (!r) {
            DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
            free(entry);
            return -1;
        }
        strlcpy(r->name, name, MAX_FQDN_LEN);
        r->code = alloc_fqdn_code(hdl);
        if (r->code == -1) {
            free(entry);
            free(r);
            return -1;
        }
        r->vh = vh;
        if (is_fqdn_name_wildcard(r->name)) {
            r->flag = FQDN_RECORD_WILDCARD;
        }
        entry->r = r;
        rcu_map_add(&hdl->fqdn_name_map, entry, name);
        th_counter.domains++;
        DEBUG_POLICY("create record name:%s code %x flag 0x%08x vh(%d)\n", r->name, r->code, r->flag, r->vh);
    } else {
        r = name_entry->r;
        r->vh = vh;
        if (r->flag & FQDN_RECORD_WILDCARD) {
            r->flag = FQDN_RECORD_WILDCARD;
        } else {
            r->flag = 0;
        }
        DEBUG_POLICY("existing record name:%s code %x flag 0x%08x vh(%d)\n", r->name, r->code, r->flag, r->vh);
    }

    if (ip == 0) {
        // It is fine if ip is not provided from ctrl.
        // Maybe it just cannot be resolved at the moment.
        return r->code;
    }

    ipv4_entry = rcu_map_lookup(&hdl->fqdn_ipv4_map, &ip);
    if (!ipv4_entry) {
        fqdn_ipv4_entry_t *entry;
        entry = (fqdn_ipv4_entry_t *)calloc(1, sizeof(fqdn_ipv4_entry_t));
        if (!entry) {
            DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
        } else {
            entry->ip = ip;
            if (config_record_ip_list(entry, r) < 0){
                free(entry);
                return r->code;
            }
            rcu_map_add(&hdl->fqdn_ipv4_map, entry, &ip);
            th_counter.domain_ips++;
            DEBUG_POLICY("create record ip:%x name:%s code %x\n", ip, name, r->code);
        }
    } else {
        config_record_ip_list(ipv4_entry, r);
    }
    return r->code;
}

static bool match_fqdn_wildcard_name(char *vhost, char *fqdname)
{
    char dname[MAX_FQDN_LEN];
    int i, j;

    strlcpy(dname, vhost, MAX_FQDN_LEN);
    //dname is null terminated
    for (j = strlen(dname)-2; j > 0;  j--) {
        if (dname[j] == '.') {
            break;
        }
    }
    for (i = 0; i < j-1; i++) {
        if (dname[i+1] == '.') {
            dname[i] = '*';
            if (strcasecmp(fqdname, &dname[i]) == 0) {
                return true;
            }
        }
    }
    return false;
}
// Called by policy lookup
static int policy_match_ipv4_fqdn_code(dpi_fqdn_hdl_t *fqdn_hdl, uint32_t ip, dpi_policy_hdl_t *hdl, dpi_rule_key_t *key,
                                     int is_ingress, dpi_policy_desc_t *desc2, dpi_packet_t *p)
{
    dpi_session_t *s = NULL;
    fqdn_ipv4_entry_t *ipv4_entry;
    ipv4_entry = rcu_map_lookup(&fqdn_hdl->fqdn_ipv4_map, &ip);
    if (!ipv4_entry) {
        return 0;
    } else {
        DEBUG_POLICY("found ip %x\n", ip);
        if(ipv4_entry->rlist.prev==NULL && ipv4_entry->rlist.next==NULL) {
            CDS_INIT_LIST_HEAD(&ipv4_entry->rlist);
        }
        //ctrl path does not reach here, only dp does.
        //For safety we still check whether p is NULL.
        if (p) {
            s = p->session;
        }
        fqdn_record_item_t *r_itr, *r_next;
        int i = 0;
        cds_list_for_each_entry_safe(r_itr, r_next, &ipv4_entry->rlist, node) {
            //multiple FQDN can map to same IP
            dpi_policy_desc_t desc3;
            bool wildmatch = false;
            if (r_itr->r->code != 0) {
                if (is_ingress) {
                    key->sip = r_itr->r->code;
                } else {
                    key->dip = r_itr->r->code;
                }
                _dpi_policy_lookup_by_key(hdl, key, is_ingress, &desc3);
                if (r_itr->r->vh) {
                    //vhost based FQDN group, we need to match vhost in the session
                    if (s && FLAGS_TEST(s->flags, DPI_SESS_FLAG_POLICY_APP_READY)) {
                        if (desc3.id > 0) {//not implicit
                            if (r_itr->r->flag & FQDN_RECORD_WILDCARD) {
                                wildmatch = match_fqdn_wildcard_name((char *)s->vhost, r_itr->r->name);
                            }
                            //if we cannot match vhost in session with name in fqdn record
                            //it means no match, set to implicit default
                            if (s->vhlen == 0 || (strcasecmp(r_itr->r->name,(char *)s->vhost) != 0 && !wildmatch)) {
                                desc3.id = 0;
                                desc3.action = hdl->def_action;
                                //desc3->flags = POLICY_DESC_CHECK_VER;
                                desc3.order = 0xffffffff;
                                desc3.hdl_ver = 0;
                            }
                        }
                    } else {
                        //we need vhost in session to do exact match
                        //if action is check_app we do not change to check_vh
                        //because check_app will also reevaluate, by the time
                        //app is ready, vhost should also be ready
                        if (desc3.id > 0 && desc3.action != DP_POLICY_ACTION_CHECK_APP) {
                            desc3.action = DP_POLICY_ACTION_CHECK_VH;
                        }
                    }
                }
                if (i == 0) {
                    policy_desc_cpy(desc2, &desc3);
                } else {
                    policy_desc_merge(desc2, &desc3);
                }
                i++;
            }
        }
        return i;
    }
}

//caller make sure hdl, name_entry and ip not NULL
static int associate_ip_record(dpi_fqdn_hdl_t *hdl, fqdn_name_entry_t *name_entry, uint32_t *ip, int cnt)
{
    fqdn_ipv4_entry_t *ipv4_entry = NULL;
    int i, ret;
    bool new_ip = false;
    for (i = 0; i < cnt; i++) {
        ipv4_entry = rcu_map_lookup(&hdl->fqdn_ipv4_map, &ip[i]);
        if (ipv4_entry) {
            ret = config_record_ip_list(ipv4_entry, name_entry->r);
            //existing ip entry associated with wildcard fqdn
            if ((ret == 1) && (name_entry->r->flag & FQDN_RECORD_WILDCARD)) {
                new_ip = true;
            }
        } else {
            ipv4_entry = (fqdn_ipv4_entry_t *)calloc(1, sizeof(fqdn_ipv4_entry_t));
            if (!ipv4_entry) {
                DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
                return -1;
            }
            ipv4_entry->ip = ip[i];
            if (config_record_ip_list(ipv4_entry, name_entry->r) < 0){
                free(ipv4_entry);
                return -1;
            }
            th_counter.domain_ips++;
            rcu_map_add(&hdl->fqdn_ipv4_map, ipv4_entry, &ipv4_entry->ip);
            DEBUG_POLICY("create record ip: %x name: %s code %x\n",
                            ipv4_entry->ip, name_entry->r->name, name_entry->r->code);
            if (name_entry->r->flag & FQDN_RECORD_WILDCARD) {
                new_ip = true;
            }
        }
    }
    if (new_ip) {
        uatomic_set(&name_entry->r->record_updated, 1);
    }
    return 0;
}

// Called from parser
int snooped_fqdn_ipv4_mapping(char *name, uint32_t *ip, int cnt)
{
    fqdn_name_entry_t *name_entry = NULL;
    dpi_fqdn_hdl_t *hdl = g_fqdn_hdl;

    //name is null terminated
    if (strlen(name) > 0) {
        lower_string(name);
    }
    DEBUG_POLICY("name: (%s) ip cnt: (%d)\n", name, cnt);

    name_entry = rcu_map_lookup(&hdl->fqdn_name_map, name);
    if (name_entry &&
        !(name_entry->r->flag & (FQDN_RECORD_TO_DELETE|FQDN_RECORD_DELETED))) {
        DEBUG_POLICY("exact match name: (%s)\n", name);
        associate_ip_record(hdl, name_entry, ip, cnt);
    }
    char dname[MAX_FQDN_LEN];
    int i, j;

    strlcpy(dname, name, MAX_FQDN_LEN);
    //dname is null terminated
    for (j = strlen(dname)-2; j > 0;  j--) {
        if (dname[j] == '.') {
            break;
        }
    }
    for (i = 0; i < j-1; i++) {
        if (dname[i+1] == '.') {
            dname[i] = '*';
            name_entry = rcu_map_lookup(&hdl->fqdn_name_map, &dname[i]);
            if (name_entry &&
                !(name_entry->r->flag & (FQDN_RECORD_TO_DELETE|FQDN_RECORD_DELETED))) {
                DEBUG_POLICY("wildcard match name: (%s)\n", &dname[i]);
                associate_ip_record(hdl, name_entry, ip, cnt);
            }
        }
    }
    return 0;
}

static int enqueue_fqdn_name_to_del(dpi_fqdn_hdl_t *hdl, fqdn_name_entry_t *entry)
{
    if (hdl->del_name_cnt == DPI_FQDN_DELETE_QLEN) {
       return -1;
    }
    entry->r->flag |= FQDN_RECORD_DELETED;
    hdl->del_name_list[hdl->del_name_cnt] = entry;
    hdl->del_name_cnt++;
    return 0;
}

static int enqueue_fqdn_ipv4_to_del(dpi_fqdn_hdl_t *hdl, fqdn_ipv4_entry_t *entry)
{
    if (hdl->del_ipv4_cnt == DPI_FQDN_DELETE_QLEN) {
       return -1;
    }
    hdl->del_ipv4_list[hdl->del_ipv4_cnt] = entry;
    hdl->del_ipv4_cnt++;
    return 0;
}

static void free_fqdn_ipv4(dpi_fqdn_hdl_t *hdl)
{
    int i;
    for (i = 0; i < hdl->del_ipv4_cnt; i++) {
        //DEBUG_POLICY("Free fqdn ipv4 %x\n", hdl->del_ipv4_list[i]->ip);
        free(hdl->del_ipv4_list[i]);
        hdl->del_ipv4_list[i] = NULL;
        th_counter.domain_ips--;
    }
    hdl->del_ipv4_cnt = 0;
}

static void free_fqdn_name(dpi_fqdn_hdl_t *hdl)
{
    int i = 0;
    fqdn_record_t *r;
    for (i = 0; i < hdl->del_name_cnt; i++) {
        r = hdl->del_name_list[i]->r;
        if(r->iplist.prev==NULL && r->iplist.next==NULL) {
            CDS_INIT_LIST_HEAD(&r->iplist);
        }
        //release ipv4_item list(r->iplist) first
        fqdn_ipv4_item_t *ipv4_itr, *ipv4_next;
        cds_list_for_each_entry_safe(ipv4_itr, ipv4_next, &r->iplist, node) {
            cds_list_del((struct cds_list_head *)ipv4_itr);
            free(ipv4_itr);
            r->ip_cnt--;
        }
        DEBUG_POLICY("Free fqdn name %s code %x ip_cnt %d\n", r->name, r->code, r->ip_cnt);
        free_fqdn_code(hdl, r->code);
        free(r);
        free(hdl->del_name_list[i]);
        hdl->del_name_list[i] = NULL;
        th_counter.domains--;
    }
    hdl->del_name_cnt = 0;

    fqdn_record_item_t *r_itr, *r_next;
    cds_list_for_each_entry_safe(r_itr, r_next, &hdl->del_rlist, node) {
        DEBUG_POLICY("free fqdn_record_item_t %s\n", r_itr->r->name);
        cds_list_del((struct cds_list_head *)r_itr);
        free(r_itr);
    }
}

bool check_fqdn_name_entry(struct cds_lfht_node *ht_node, void *args)
{
    fqdn_name_entry_t *entry = (fqdn_name_entry_t *)ht_node;
    fqdn_iter_ctx_t *ctx = (fqdn_iter_ctx_t *)args;

    if (entry->r->flag & FQDN_RECORD_TO_DELETE) {
        if (enqueue_fqdn_name_to_del(ctx->hdl, entry) == 0) {
            DEBUG_POLICY("Delete fqdn name record %s ref %d\n",
                         entry->r->name, entry->r->ip_cnt);
            rcu_map_del(&ctx->hdl->fqdn_name_map, ht_node);
        } else {
            // Tell the caller that this record is not deleted successfully
            // due to queue full
            ctx->more = true;
            return true;
        }
    }
    return false;
}

bool check_fqdn_ipv4_entry(struct cds_lfht_node *ht_node, void *args)
{
    fqdn_iter_ctx_t *ctx = (fqdn_iter_ctx_t *)args;
    fqdn_ipv4_entry_t *entry = (fqdn_ipv4_entry_t *)ht_node;
    fqdn_record_item_t *r_itr, *r_next;
    if(entry->rlist.prev==NULL && entry->rlist.next==NULL) {
        CDS_INIT_LIST_HEAD(&entry->rlist);
    }
    cds_list_for_each_entry_safe(r_itr, r_next, &entry->rlist, node) {
        if (r_itr->r->flag & FQDN_RECORD_DELETED) {
            cds_list_del((struct cds_list_head *)r_itr);
            //free(r_itr);
            cds_list_add_tail((struct cds_list_head *)r_itr, &(ctx->hdl->del_rlist));
        }
    }
    if (cds_list_empty(&entry->rlist)) {
        if (enqueue_fqdn_ipv4_to_del(ctx->hdl, entry) == 0) {
            DEBUG_POLICY("Delete fqdn ipv4 record %x\n", entry->ip);
            rcu_map_del(&ctx->hdl->fqdn_ipv4_map, ht_node);
        } else {
            // Tell the caller that this record is not deleted successfully
            // due to queue full
            ctx->more = true;
            return true;
        }
    }
    return false;
}

void dpi_fqdn_entry_mark_delete(const char *name)
{
    fqdn_name_entry_t *entry;

    entry = rcu_map_lookup(&g_fqdn_hdl->fqdn_name_map, name);
    if (entry) {
        entry->r->flag |= FQDN_RECORD_TO_DELETE;
    }
}

void dpi_fqdn_entry_delete_marked()
{
    fqdn_iter_ctx_t ctx;
    bool more = true;

    memset(&ctx, 0, sizeof(ctx));
    ctx.hdl = g_fqdn_hdl;

    while (more) {
        ctx.more = false;
        rcu_read_lock();
        rcu_map_for_each(&ctx.hdl->fqdn_name_map, check_fqdn_name_entry, &ctx);
        rcu_read_unlock();
        more = ctx.more;

        if (ctx.hdl->del_name_cnt > 0) {
            bool rcu_synced = false;
            do {
                ctx.more = false;
                rcu_read_lock();
                rcu_map_for_each(&ctx.hdl->fqdn_ipv4_map, check_fqdn_ipv4_entry, &ctx);
                rcu_read_unlock();
                if (ctx.hdl->del_ipv4_cnt > 0) {
                    rcu_synced = true;
                    synchronize_rcu();
                    free_fqdn_ipv4(ctx.hdl);
                }
            } while(ctx.more);
            if (!rcu_synced) {
                synchronize_rcu();
            }
            free_fqdn_name(ctx.hdl);
        }
    }
    return;
}

int dpi_policy_init() {
    g_fqdn_hdl = dpi_fqdn_hdl_init();
    if (g_fqdn_hdl == NULL) {
        DEBUG_ERROR(DBG_POLICY, "Fail to init fqdn hdl!!!\n");
        return -1;
    }
    return 0;
}

/*
 * -----------------------------------------
 * --- ip-fqdn storage definition ----------
 * -----------------------------------------
 */
static int ip_fqdn_storage_match(struct cds_lfht_node *ht_node, const void *key)
{
    dpi_ip_fqdn_storage_entry_t *s = STRUCT_OF(ht_node, dpi_ip_fqdn_storage_entry_t, node);
    const uint32_t *k = key;
    return (s->r->ip == *k);
}

static uint32_t ip_fqdn_storage_hash(const void *key)
{
    const uint32_t *k = key;
    return sdbm_hash((uint8_t *)k, sizeof(uint32_t));
}

static void ip_fqdn_storage_release(timer_entry_t *entry)
{
    dpi_ip_fqdn_storage_entry_t *c = STRUCT_OF(entry, dpi_ip_fqdn_storage_entry_t, ts_entry);
    rcu_map_del(&th_ip_fqdn_storage_map, c);    
    dp_ctrl_release_ip_fqdn_storage(c);
    free(c);
}

void dpi_ip_fqdn_storage_init(void)
{
    rcu_map_init(&th_ip_fqdn_storage_map, 64, offsetof(dpi_ip_fqdn_storage_entry_t, node), ip_fqdn_storage_match, ip_fqdn_storage_hash);
}

static void add_ip_fqdn_storage_entry(char *name, uint32_t ip)
{
    dpi_ip_fqdn_storage_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
        return;
    }

    dpi_ip_fqdn_storage_record_t *r = calloc(1, sizeof(*r));
    if (!r) {
        DEBUG_ERROR(DBG_POLICY, "OOM!!!\n");
        free(entry);
        return;
    }
    r->ip = ip;
    strlcpy(r->name, name, MAX_FQDN_LEN);
    uatomic_set(&r->record_updated, 1);
    entry->r = r;
    rcu_map_add(&th_ip_fqdn_storage_map, entry, &ip);

    timer_wheel_entry_init(&entry->ts_entry);
    timer_wheel_entry_start(&th_timer, &entry->ts_entry,
                            ip_fqdn_storage_release, IP_FQDN_STORAGE_ENTRY_TIMEOUT, th_snap.tick);
}

static void update_ip_fqdn_storage_entry(dpi_ip_fqdn_storage_entry_t *entry, char *name)
{
    strlcpy(entry->r->name, name, MAX_FQDN_LEN);
    uatomic_set(&entry->r->record_updated, 1);

    timer_wheel_entry_refresh(&th_timer, &entry->ts_entry, th_snap.tick);
}

// Called from parser, make sure ip not NULL
int sniff_ip_fqdn_storage(char *name, uint32_t *ip, int cnt)
{
    DEBUG_POLICY("name: (%s), ip cnt: (%d)\n", name, cnt);

    int i;
    for (i = 0; i < cnt; i++)
    {
        if (!dpi_is_ip4_internal(ip[i])) {
            dpi_ip_fqdn_storage_entry_t *ip_fqdn_storage_entry = rcu_map_lookup(&th_ip_fqdn_storage_map, &ip[i]);
            if (!ip_fqdn_storage_entry) {
                add_ip_fqdn_storage_entry(name, ip[i]);
            }
            else {
                if (strcmp(ip_fqdn_storage_entry->r->name, name) != 0) {
                    update_ip_fqdn_storage_entry(ip_fqdn_storage_entry, name);
                }
            }
        }
    }
    return 0;
}
