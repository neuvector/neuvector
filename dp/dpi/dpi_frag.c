#include <stdio.h>
#include <string.h>

#include "utils/rcu_map.h"

#include "utils/helper.h"
#include "utils/asm.h"
#include "dpi/dpi_module.h"

#define DPI_FRAG_TIMEOUT 10

#define FRAG_TRAC_COMMON       \
    struct cds_lfht_node node; \
    timer_entry_t ts_entry;      \
    uint32_t length : 30,      \
             first  : 1,       \
             last   : 1;       \
    asm_t frags;               \


typedef struct frag_trac_ {
    FRAG_TRAC_COMMON;
} frag_trac_t;

typedef struct ipfrag_trac_ {
    FRAG_TRAC_COMMON;

    uint32_t src, dst;
    uint16_t ipid;
    bool ingress;
    uint8_t pad;
} ip4frag_trac_t;


typedef struct teardrop_args_ {
    uint32_t seq;
    uint32_t len;
    bool overlap;
} teardrop_args_t;


static int ip4frag_trac_match(struct cds_lfht_node *ht_node, const void *key)
{
    ip4frag_trac_t *t1 = STRUCT_OF(ht_node, ip4frag_trac_t, node);
    const ip4frag_trac_t *t2 = key;

    return t1->src == t2->src && t1->dst == t2->dst && t1->ipid == t2->ipid && t1->ingress == t2->ingress;
}

static uint32_t ip4frag_trac_hash(const void *key)
{
    const ip4frag_trac_t *t = key;

    return sdbm_hash((uint8_t *)&t->src, sizeof(t->src)) +
           sdbm_hash((uint8_t *)&t->dst, sizeof(t->dst)) + t->ipid;
}

static void ipfrag_remove(clip_t *clip)
{
    th_counter.freed_frags ++;
    free(clip);
}

static void teardrop_check(clip_t *clip, void *args)
{
    teardrop_args_t *td = args;

    if (!td->overlap) {
        td->overlap = u32_overlap(td->seq, td->seq + td->len, clip->seq, clip->seq + clip->len);
    }
}


static void ipfrag_hold(ip4frag_trac_t *trac, dpi_packet_t *p)
{
    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
    uint32_t frag_off, seq, len, end;

    frag_off = ntohs(iph->frag_off);
    seq = (frag_off & IP_OFFMASK) << 3;
    len = p->len - p->l4;
    end = seq + len;

    if (len == 0) {
        return;
    }

    // Check teardrop
    if (asm_count(&trac->frags) > 0) {
        teardrop_args_t td;
        td.seq = seq;
        td.len = len;
        td.overlap = false;
        asm_foreach(&trac->frags, teardrop_check, &td);
        if (td.overlap) {
            dpi_threat_trigger(DPI_THRT_IP_TEARDROP, p, NULL);
            return;
        }
    }

    if (seq == 0) {
        trac->first = 1;
    }

    if (frag_off & IP_MF) {
        // more
        if (end > trac->length) {
            if (trac->last) {
                return;
            }
            trac->length = end;
        }
    } else {
        // last
        if (end < trac->length || (trac->last && end != trac->length)) {
            return;
        }
        trac->last = 1;
        trac->length = end;
    }

    // Save the fragment
    clip_t *clip = malloc(sizeof(*clip) + p->cap_len);
    if (clip == NULL) {
        return;
    }

    th_counter.total_frags ++;
    clip->seq = seq;
    clip->skip = p->l4;
    clip->len = len;
    clip->ptr = (uint8_t *)(clip + 1);
    memcpy(clip->ptr, p->pkt, p->cap_len);

    if (asm_insert(&trac->frags, clip) == ASM_FAILURE) {
        ipfrag_remove(clip);
        DEBUG_ERROR(DBG_PACKET, "Fail to save ipv4 fragment, seq=%u len=%u\n", seq, len);
    } else {
        DEBUG_LOG(DBG_PACKET, NULL, "Save ipv4 fragment, seq=%u len=%u\n", seq, len);
    }
}

static bool ipfrag_construct(ip4frag_trac_t *trac, dpi_packet_t *p)
{
    struct iphdr *iph;
    clip_t cons;
    asm_result_t ret;

    cons.seq = 0;
    cons.ptr = p->defrag_data + p->l4;
    cons.len = DPI_MAX_PKT_LEN - p->l4;

    ret = asm_construct(&trac->frags, &cons, trac->length - 1);
    if (ret == ASM_OK) {
        iph = (struct iphdr *)(p->defrag_data + p->l3);

        DEBUG_LOG(DBG_PACKET, NULL, "Assembled ipv4 fragment, len=%u\n", trac->length);

        // Copy L2/L3 header of the current packet
        memcpy(p->defrag_data, p->pkt, p->l4);

        iph->frag_off = 0;
        iph->tot_len = htons(p->l4 - p->l3 + cons.len);

        iph->check = 0;
        iph->check = get_ip_cksum(iph);

        p->pkt = p->defrag_data;
        p->cap_len = p->len = p->l4 + cons.len;

        // Remove trac from the map, keep it to send packets
        rcu_map_del(&th_ip4frag_map, trac);
        timer_wheel_entry_remove(&th_timer, &trac->ts_entry);
        p->frag_trac = trac;

        return 0;
    }

    return -1;
}

static void ipfrag_release(timer_entry_t *entry)
{
    ip4frag_trac_t *trac = STRUCT_OF(entry, ip4frag_trac_t, ts_entry);

    rcu_map_del(&th_ip4frag_map, trac);

    // TODO: should track the sender
    th_counter.tmout_frags ++;
    asm_destroy(&trac->frags, ipfrag_remove);
    free(trac);
}

int dpi_ip_defrag(dpi_packet_t *p)
{
    ip4frag_trac_t *trac, key;
    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
    int ret = -1;

    memset(&key, 0, sizeof(key));
    key.src = iph->saddr;
    key.dst = iph->daddr;
    key.ipid = iph->id;
    key.ingress = !!(p->flags & DPI_PKT_FLAG_INGRESS);

    trac = rcu_map_lookup(&th_ip4frag_map, &key);
    if (trac == NULL) {
        trac = malloc(sizeof(*trac));
        if (trac == NULL) {
            return -1;
        }

        memcpy(trac, &key, sizeof(key));
        asm_init(&trac->frags);

        rcu_map_add(&th_ip4frag_map, trac, &key);
        timer_wheel_entry_init(&trac->ts_entry);
        timer_wheel_entry_start(&th_timer, &trac->ts_entry,
                                ipfrag_release, DPI_FRAG_TIMEOUT, th_snap.tick);
    }

    timer_wheel_entry_refresh(&th_timer, &trac->ts_entry, th_snap.tick);

    ipfrag_hold(trac, p);
    if (trac->first && trac->last) {
        ret = ipfrag_construct(trac, p);
    }

    return ret;
}

// ---- ipv6

typedef struct ip6frag_trac_ {
    FRAG_TRAC_COMMON;

    struct in6_addr src, dst;
    uint16_t ipid;
    uint8_t next_header;
    bool ingress;
} ip6frag_trac_t;

static int ip6frag_trac_match(struct cds_lfht_node *ht_node, const void *key)
{
    ip6frag_trac_t *t1 = STRUCT_OF(ht_node, ip6frag_trac_t, node);
    const ip6frag_trac_t *t2 = key;

    return (memcmp(&t1->src, &t2->src, sizeof(t1->src)) == 0 &&
            memcmp(&t1->dst, &t2->dst, sizeof(t1->dst)) == 0 &&
            t1->ipid == t2->ipid && t1->ingress == t2->ingress) ? 1 : 0;
}

static uint32_t ip6frag_trac_hash(const void *key)
{
    const ip6frag_trac_t *t = key;

    return sdbm_hash((uint8_t *)&t->src, sizeof(t->src)) +
           sdbm_hash((uint8_t *)&t->dst, sizeof(t->dst)) + t->ipid;
}

static void ip6frag_hold(ip6frag_trac_t *trac, dpi_packet_t *p)
{
    uint32_t frag_off, seq, len, end;

    frag_off = ntohs(p->ip6_fragh->ip6f_offlg);
    seq = frag_off & IP6F_OFF_MASK;
    len = p->len - p->l4;
    end = seq + len;

    if (seq == 0) {
        trac->first = 1;
        trac->next_header = p->ip6_fragh->ip6f_nxt;
    }

    if (frag_off & IP6F_MORE_FRAG) {
        // more
        if (end > trac->length) {
            if (trac->last) {
                return;
            }
            trac->length = end;
        }
    } else {
        // last
        if (end < trac->length || (trac->last && end != trac->length)) {
            return;
        }
        trac->last = 1;
        trac->length = end;
    }

    clip_t *clip = malloc(sizeof(*clip) + p->cap_len);
    if (clip == NULL) {
        return;
    }

    th_counter.total_frags ++;
    clip->seq = seq;
    clip->skip = p->l4;
    clip->len = len;
    clip->ptr = (uint8_t *)(clip + 1);
    memcpy(clip->ptr, p->pkt, p->cap_len);

    if (asm_insert(&trac->frags, clip) == ASM_FAILURE) {
        ipfrag_remove(clip); 
        DEBUG_ERROR(DBG_PACKET, "Fail to save ipv6 fragment, seq=%u len=%u\n", seq, len);
    } else {
        DEBUG_LOG(DBG_PACKET, NULL, "Save ipv6 fragment, seq=%u len=%u\n", seq, len);
    }   
}

static bool ip6frag_construct(ip6frag_trac_t *trac, dpi_packet_t *p)
{
    struct ip6_hdr *ip6h;
    clip_t cons;
    asm_result_t ret;

    // Only to keep IPv6 header with ext.
    cons.seq = 0;
    cons.ptr = p->defrag_data + p->l3 + sizeof(*ip6h);
    cons.len = DPI_MAX_PKT_LEN - p->l3 - sizeof(*ip6h);

    ret = asm_construct(&trac->frags, &cons, trac->length - 1);
    if (ret == ASM_OK) {
        ip6h = (struct ip6_hdr *)(p->defrag_data + p->l3);

        DEBUG_LOG(DBG_PACKET, NULL, "Assembled ipv6 fragment, len=%u\n", trac->length);

        memcpy(p->defrag_data, p->pkt, p->l3 + sizeof(*ip6h));

        ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt = trac->next_header;
        ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(cons.len);

        p->pkt = p->defrag_data;
        p->cap_len = p->len = p->l3 + sizeof(*ip6h) + cons.len;
        p->l4 = p->l3 + sizeof(*ip6h);

        // Remove trac from the map, keep it to send packets
        rcu_map_del(&th_ip4frag_map, trac);
        timer_wheel_entry_remove(&th_timer, &trac->ts_entry);
        p->frag_trac = trac;

        return 0;
    }

    return -1;
}

static void ip6frag_release(timer_entry_t *entry)
{
    ip6frag_trac_t *trac = STRUCT_OF(entry, ip6frag_trac_t, ts_entry);

    rcu_map_del(&th_ip4frag_map, trac);

    // TODO: should track the sender
    th_counter.tmout_frags ++;
    asm_destroy(&trac->frags, ipfrag_remove);
    free(trac);
}

int dpi_ipv6_defrag(dpi_packet_t *p)
{
    ip6frag_trac_t *trac, key;
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
    int ret = -1;

    memset(&key, 0, sizeof(key));
    key.src = ip6h->ip6_src;
    key.dst = ip6h->ip6_dst;
    key.ipid = p->ip6_fragh->ip6f_ident;
    key.ingress = !!(p->flags & DPI_PKT_FLAG_INGRESS);

    trac = rcu_map_lookup(&th_ip6frag_map, &key);
    if (trac == NULL) {
        // offset is 0 and no more fragments, this is a pseudo frag header
        uint16_t frag_off;
        frag_off = ntohs(p->ip6_fragh->ip6f_offlg);
        if ((frag_off & IP6F_OFF_MASK) == 0 && (frag_off & IP6F_MORE_FRAG) == 0) {
            return 0;
        }

        trac = malloc(sizeof(*trac));
        if (trac == NULL) {
            return -1;
        }

        memcpy(trac, &key, sizeof(key));
        asm_init(&trac->frags);

        rcu_map_add(&th_ip6frag_map, trac, &key);
        timer_wheel_entry_init(&trac->ts_entry);
        timer_wheel_entry_start(&th_timer, &trac->ts_entry,
                                ip6frag_release, DPI_FRAG_TIMEOUT, th_snap.tick);
    }

    timer_wheel_entry_refresh(&th_timer, &trac->ts_entry, th_snap.tick);

    ip6frag_hold(trac, p);
    if (trac->first && trac->last) {
        ret = ip6frag_construct(trac, p);
    }

    return ret;
}

// ---- 

static void send_frag(clip_t *clip, void *args)
{
    g_io_callback->send_packet(args, clip->ptr, clip->len + clip->skip);
}

void dpi_frag_discard(void *frag_trac)
{
    frag_trac_t *trac = frag_trac;
    asm_destroy(&trac->frags, ipfrag_remove);
    free(trac);
}

void dpi_frag_send(void *frag_trac, io_ctx_t *ctx)
{
    frag_trac_t *trac = frag_trac;
    asm_foreach(&trac->frags, send_frag, ctx);
    asm_destroy(&trac->frags, ipfrag_remove);
    free(trac);
}

void dpi_frag_init(void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT, NULL);

    rcu_map_init(&th_ip4frag_map, 1, offsetof(ip4frag_trac_t, node),
                 ip4frag_trac_match, ip4frag_trac_hash);
    rcu_map_init(&th_ip6frag_map, 1, offsetof(ip6frag_trac_t, node),
                 ip6frag_trac_match, ip6frag_trac_hash);
}
