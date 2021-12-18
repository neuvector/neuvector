#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "apis.h"
#include "utils/helper.h"
#include "utils/bits.h"
#include "dpi/dpi_module.h"

#define LOG_BAD_PKT(p, format, args...) \
        dpi_threat_trigger(DPI_THRT_BAD_PACKET, p, format, ##args)

extern dpi_session_t *dpi_session_lookup(dpi_packet_t *p);
extern void dpi_tcp_tracker(dpi_packet_t *p);
extern void dpi_udp_tracker(dpi_packet_t *p);
extern void dpi_icmp_tracker(dpi_packet_t *p);
extern void dpi_ip_tracker(dpi_packet_t *p);
extern bool dpi_process_detector(dpi_packet_t *p);
extern bool cmp_mac_prefix(void *m1, void *prefix);
extern bool dpi_dlp_ep_policy_check(dpi_packet_t *p);
extern bool dpi_waf_ep_policy_check(dpi_packet_t *p);

static uint16_t get_l4_cksum(uint32_t sum, void *l4_hdr, uint16_t l4_len)
{
    register uint16_t *ptr;
    register int len, i;

    ptr = l4_hdr;
    len = l4_len >> 1;
    for (i = 0; i < len; i ++, ptr ++) {
        sum += *ptr;
    }

    if (l4_len & 1) {
        sum += *ptr & htons(0xff00);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t get_l4v6_cksum(struct ip6_hdr *ip6h, uint8_t ip_proto, void *l4_hdr, uint16_t l4_len)
{
    register uint32_t sum = 0;
    register uint16_t *ptr;
    register int i;

    union {
        struct {
            struct in6_addr src;
            struct in6_addr dst;
            uint32_t len;
            uint8_t zero[3];
            uint8_t next_header;
        } ph;
        uint16_t ph16[20];
    } u;

    u.ph.src = ip6h->ip6_src;
    u.ph.dst = ip6h->ip6_dst;
    u.ph.len = htons(l4_len);
    u.ph.zero[0] = u.ph.zero[1] = u.ph.zero[2] = 0;
    u.ph.next_header = ip_proto;

    ptr = &u.ph16[0];
    for (i = 0; i < 20; i ++, ptr ++) {
        sum += *ptr;
    }

    return get_l4_cksum(sum, l4_hdr, l4_len);
}

uint16_t get_l4v4_cksum(struct iphdr *iph, void *l4_hdr, uint16_t l4_len)
{
    register uint32_t sum = 0;
    register uint16_t *ptr;
    register int i;

    if (iph != NULL) {
        union {
            struct {
                uint32_t src;
                uint32_t dst;
                uint8_t zero;
                uint8_t proto;
                uint16_t len;
            } ph;
            uint16_t ph16[6];
        } u;

        u.ph.src = iph->saddr;
        u.ph.dst = iph->daddr;
        u.ph.zero = 0;
        u.ph.proto = iph->protocol;
        u.ph.len = htons(l4_len);

        ptr = &u.ph16[0];
        for (i = 0; i < 6; i ++, ptr ++) {
            sum += *ptr;
        }
    }

    return get_l4_cksum(sum, l4_hdr, l4_len);
}

uint16_t get_ip_cksum(struct iphdr *iph)
{
    register uint16_t *ptr = (uint16_t *)iph;
    register int len = get_iph_len(iph) >> 1;
    register uint32_t sum = 0;

    while (len --) {
        sum += *ptr ++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

int dpi_parse_embed_icmp(dpi_packet_t *p)
{
    struct icmphdr *icmph = (struct icmphdr *)(p->pkt + p->l4);
    uint16_t icmp_len = p->len - p->l4;
    struct iphdr *iph;
    uint16_t ip_len, iph_len;
    dpi_session_t *t_sess = NULL;
    dpi_packet_t lpacket;

    if (icmp_len < sizeof(*icmph) + sizeof(struct iphdr)) {
        DEBUG_LEVEL(DBG_PACKET, "Embedded icmp not enough icmp len(%u) to hold ipv4 header\n", icmp_len);
        return -1;
    }

    iph = (struct iphdr *)(p->pkt + p->l4 + sizeof(*icmph));

    if (iph->version != 4) {
        DEBUG_LEVEL(DBG_PACKET, "Embedded icmp bad ip version %u\n", iph->version);
        return -1;
    }

    ip_len = ntohs(iph->tot_len);
    iph_len = get_iph_len(iph);

    if (iph_len < sizeof(*iph) || ip_len < iph_len) {
        DEBUG_LEVEL(DBG_PACKET,
                    "Embedded icmp bad ipv4 header length: ip_len=%u, hdr_len=%u\n",
                    ip_len, iph_len);
        return -1;
    }

    if (icmp_len < (sizeof(*icmph) + iph_len + 4)) {
        DEBUG_LEVEL(DBG_PACKET, "Embedded icmp not enough length(%u) to hold src/dst port\n", icmp_len);
        return -1;
    }

    /* assign value to local packet for session lookup */
    lpacket.pkt = p->pkt;
    lpacket.ip_proto = iph->protocol;
    lpacket.eth_type = p->eth_type;
    lpacket.flags = p->flags^DPI_PKT_FLAG_INGRESS;
    lpacket.sport = ntohs(*(uint16_t *)(p->pkt + p->l4 + sizeof(*icmph) + iph_len));
    lpacket.dport = ntohs(*(uint16_t *)(p->pkt + p->l4 + sizeof(*icmph) + iph_len + 2));
    lpacket.l3 = p->l4 + sizeof(*icmph);
    lpacket.ep_mac = p->ep_mac;
    DEBUG_LOG(DBG_PACKET, p, "Embedded icmp ip proto(%u), sport(%hu), dport(%hu), l3(%hu), packet flags(0x%08x)\n", 
        lpacket.ip_proto, lpacket.sport, lpacket.dport, lpacket.l3, lpacket.flags);

    t_sess = dpi_session_lookup(&lpacket);

    if (!t_sess) {
        DEBUG_LOG(DBG_PACKET, p, "Suspicious embedded icmp session not found for embedded proto(%u)\n", iph->protocol);
        return -1;
    }

    DEBUG_LOG(DBG_PACKET, p, "Embedded icmp session found for embedded proto(%u)\n", iph->protocol);
    return 0;
}

static int dpi_parse_ipv6_ext4embed_icmp(struct ip6_hdr *ip6h, uint8_t *ptr, uint8_t *end, uint8_t *protocol)
{
    int ext_len;
    bool hopopts = false;
    uint8_t type = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    while (ptr < end) {
        switch (type) {
        case IPPROTO_FRAGMENT:
            ext_len = 8;
            break;
        case IPPROTO_AH:
            if (ptr + 1 >= end) {
                return -1;
            }
            ext_len = (*(ptr + 1) + 2) << 2;
            break;
        case IPPROTO_HOPOPTS:
            if (hopopts) {
                return -1;
            }
            hopopts = true;
            // fall through
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
            if (ptr + 1 >= end) {
                return -1;
            }
            ext_len = (*(ptr + 1) + 1) << 3;
            break;
        case IPPROTO_NONE:
        default:
            *protocol = type;
            return ptr - (uint8_t *)ip6h;
        }

        if (ext_len <= 2) {
            return -1;
        }

        type = *ptr;
        ptr += ext_len;
    }

    return -1;
}

int dpi_parse_embed_icmpv6(dpi_packet_t *p)
{
    struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)(p->pkt + p->l4);
    uint16_t icmp6_len = p->len - p->l4;
    struct ip6_hdr *ip6h;
    int offset;
    uint8_t *ptr, *end;
    uint8_t protocol = 0;
    dpi_session_t *t_sess = NULL;
    dpi_packet_t lpacket;

    if (icmp6_len < sizeof(*icmp6h) + sizeof(struct ip6_hdr)) {
        DEBUG_LEVEL(DBG_PACKET, "Embedded icmpv6 not enough len(%u) to hold embedded ipv6 header\n", icmp6_len);
        return -1;
    }

    ip6h = (struct ip6_hdr *)(p->pkt + p->l4 + sizeof(*icmp6h));

    ptr = (uint8_t *)(ip6h + 1);
    end = p->pkt + p->len;
    offset = dpi_parse_ipv6_ext4embed_icmp(ip6h, ptr, end, &protocol);

    if (offset < 0) {
        DEBUG_LEVEL(DBG_PACKET, "Embedded icmpv6 bad ipv6 ext header\n");
        return -1;
    }

    if (icmp6_len < (sizeof(*icmp6h) + sizeof(*ip6h) + offset + 4)) {
        DEBUG_LEVEL(DBG_PACKET, "Embedded icmp6 not enough length(%u) to hold embedded src/dst port\n", icmp6_len);
        return -1;
    }

    lpacket.pkt = p->pkt;
    lpacket.ip_proto = protocol;
    lpacket.eth_type = p->eth_type;
    lpacket.flags = p->flags^DPI_PKT_FLAG_INGRESS;
    lpacket.sport = ntohs(*(uint16_t *)(p->pkt + p->l4 + sizeof(*icmp6h) + sizeof(*ip6h) + offset));
    lpacket.dport = ntohs(*(uint16_t *)(p->pkt + p->l4 + sizeof(*icmp6h) + sizeof(*ip6h) + offset + 2));
    lpacket.l3 = p->l4 + sizeof(*icmp6h);
    lpacket.ep_mac = p->ep_mac;

    DEBUG_LOG(DBG_PACKET, p, "Embedded icmpv6 ip proto(%u), sport(%hu), dport(%hu), l3(%hu), packet flags(0x%08x)\n", 
        lpacket.ip_proto, lpacket.sport, lpacket.dport, lpacket.l3, lpacket.flags);

    t_sess = dpi_session_lookup(&lpacket);

    if (!t_sess) {
        DEBUG_LOG(DBG_PACKET, p, "Suspicious embedded icmpv6 session not found for embedded proto(%u)\n", protocol);
        return -1;
    }

    DEBUG_LOG(DBG_PACKET, p, "Embedded icmpv6 session found for embedded proto(%u)\n", protocol);
    return 0;
}

static int dpi_parse_icmpv6(dpi_packet_t *p)
{
    struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)(p->pkt + p->l4);
    uint16_t icmp6_len = p->len - p->l4;
    uint16_t sport, dport;

    if (icmp6_len < sizeof(*icmp6h)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad icmp6 packet length %u\n", icmp6_len);
        LOG_BAD_PKT(p, "Bad icmp6 packet length %u", icmp6_len);
        return -1;
    }

    // Checksum
    if (unlikely(g_io_config->enable_cksum)) {
        uint16_t pkt_cksum, cksum;

        pkt_cksum = icmp6h->icmp6_cksum;
        icmp6h->icmp6_cksum = 0;
        cksum = get_l4v6_cksum((struct ip6_hdr *)(p->pkt + p->l3), IPPROTO_ICMPV6,
                               icmp6h, icmp6_len);
        icmp6h->icmp6_cksum = pkt_cksum;

        if (pkt_cksum == 0xffff) {
            pkt_cksum = 0;
        }

        if (pkt_cksum != cksum) {
            DEBUG_LEVEL(DBG_PACKET, "Bad icmp6 checksum 0x%x, should be 0x%x\n",
                                    htons(pkt_cksum), htons(cksum));
            return -1;
        }
    }

    switch (icmp6h->icmp6_type) {
    case ICMP6_ECHO_REPLY:
        sport = (icmp6h->icmp6_code << 8) | ICMP6_ECHO_REPLY;
        dport = icmp6h->icmp6_dataun.icmp6_un_data16[0];
        break;
    default:
        dpi_set_client_pkt(p);
        sport = icmp6h->icmp6_dataun.icmp6_un_data16[0];
        dport = (icmp6h->icmp6_code << 8) | icmp6h->icmp6_type;
        break;
    }

    p->sport = ntohs(sport);
    p->dport = ntohs(dport);
    p->raw.ptr = p->pkt + p->l4 + sizeof(*icmp6h);
    p->raw.len = p->len - p->l4 - sizeof(*icmp6h);

    return 0;
}

static int dpi_parse_icmp(dpi_packet_t *p)
{
    struct icmphdr *icmph = (struct icmphdr *)(p->pkt + p->l4);
    uint16_t icmp_len = p->len - p->l4;
    uint16_t sport, dport;

    if (icmp_len < sizeof(*icmph)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad icmp packet length %u\n", icmp_len);
        LOG_BAD_PKT(p, "Bad icmp packet length %u", icmp_len);
        return -1;
    }

    // Checksum
    if (unlikely(g_io_config->enable_cksum)) {
        uint16_t pkt_cksum, cksum;

        pkt_cksum = icmph->checksum;
        icmph->checksum = 0;
        cksum = get_l4v4_cksum(NULL, icmph, icmp_len);
        icmph->checksum = pkt_cksum;

        if (pkt_cksum == 0xffff) {
            pkt_cksum = 0;
        }

        if (pkt_cksum != cksum) {
            DEBUG_LEVEL(DBG_PACKET, "Bad icmp checksum 0x%x, should be 0x%x\n",
                                    htons(pkt_cksum), htons(cksum));
            icmph->checksum = cksum;
        }
    }

    switch (icmph->type) {
    case ICMP_ECHOREPLY:
        sport = (icmph->code << 8) | ICMP_ECHO;
        dport = icmph->un.echo.id;
        break;
    case ICMP_TIMESTAMPREPLY:
        sport = (icmph->code << 8) | ICMP_TIMESTAMP;
        dport = icmph->un.echo.id;
        break;
    case ICMP_INFO_REPLY:
        sport = (icmph->code << 8) | ICMP_INFO_REQUEST;
        dport = icmph->un.echo.id;
        break;
    case ICMP_ADDRESSREPLY:
        sport = (icmph->code << 8) | ICMP_ADDRESS;
        dport = icmph->un.echo.id;
        break;
    default:
        dpi_set_client_pkt(p);
        sport = icmph->un.echo.id;
        dport = (icmph->code << 8) | icmph->type;
        break;
    }
    
    p->sport = ntohs(sport);
    p->dport = ntohs(dport);
    p->raw.ptr = p->pkt + p->l4 + sizeof(*icmph);
    p->raw.len = p->len - p->l4 - sizeof(*icmph);

    return 0;
}

static int dpi_parse_udp(dpi_packet_t *p)
{
    struct udphdr *udph = (struct udphdr *)(p->pkt + p->l4);
    uint16_t udp_len = p->len - p->l4;

    if (udp_len < sizeof(*udph)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad udp packet length %u\n", udp_len);
        LOG_BAD_PKT(p, "Bad udp packet length %u", udp_len);
        return -1;
    }

    // Checksum
    if (unlikely(g_io_config->enable_cksum)) {
        uint16_t pkt_cksum, cksum;

        pkt_cksum = udph->check;
        udph->check = 0;
        if (dpi_is_ipv4(p)) {
            cksum = get_l4v4_cksum((struct iphdr *)(p->pkt + p->l3), udph, udp_len);
        } else {
            cksum = get_l4v6_cksum((struct ip6_hdr *)(p->pkt + p->l3), IPPROTO_UDP,
                                   udph, udp_len);
        }
        udph->check = pkt_cksum;
 
        if (pkt_cksum == 0xffff) {
            pkt_cksum = 0;
        }

        if (pkt_cksum != cksum) {
            DEBUG_LEVEL(DBG_PACKET, "udp checksum 0x%x, should be 0x%x\n",
                                    htons(pkt_cksum), htons(cksum));
            udph->check = cksum;
        }
    }

    p->sport = ntohs(udph->source);
    p->dport = ntohs(udph->dest);
    p->raw.ptr = p->pkt + p->l4 + sizeof(*udph);
    p->raw.len = p->len - p->l4 - sizeof(*udph);

    return 0;
}

static uint8_t tcp_opt_len[TCP_OPT_MAX] = {
    [TCP_OPT_EOL]          1,
    [TCP_OPT_NOP]          1,
    [TCP_OPT_MSS]          4,
    [TCP_OPT_WSCALE]       3,
    [TCP_OPT_SACKOK]       2,
    [TCP_OPT_ECHO]         6,
    [TCP_OPT_ECHOREPLY]    6,
    [TCP_OPT_TIMESTAMP]    10,
    [TCP_OPT_PARTIAL_PERM] 2,
    [TCP_OPT_PARTIAL_SVC]  3,
    [TCP_OPT_CC]           6,
    [TCP_OPT_CC_NEW]       6,
    [TCP_OPT_CC_ECHO]      6,
    [TCP_OPT_ALTCSUM_ALGO] 3,
    [TCP_OPT_TRAILER_CSUM] 3,
    [TCP_OPT_MD5]          18,
};

static int dpi_parse_tcp_options(dpi_packet_t *p)
{
    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
    uint8_t *ptr = (uint8_t *)tcph + sizeof(*tcph);
    uint8_t *end = (uint8_t *)tcph + get_tcph_len(tcph);
    uint8_t type, len, opt_len;

    while (ptr < end) {
        type = *ptr;
        opt_len = (type < TCP_OPT_MAX ? tcp_opt_len[type] : 0);

        if (type == TCP_OPT_EOL) {
            return 0;
        } else if (type == TCP_OPT_NOP) {
            ptr ++;
            continue;
        }

        if ((ptr + 1) >= end) {
            DEBUG_LEVEL(DBG_PACKET, "Bad tcp option %u\n", type);
            LOG_BAD_PKT(p, "Bad tcp option %u", type);
            return -1;
        }

        len = *(ptr + 1);
        if (ptr + opt_len > end || (opt_len > 1 && len != opt_len) || len < 2) {
            DEBUG_LEVEL(DBG_PACKET, "Bad tcp option length: type=%u len=%u\n", type, len);
            LOG_BAD_PKT(p, "Bad tcp option length: type=%u len=%u", type, len);
            return -1;
        }

        if (type == TCP_OPT_SACK && len <= 2 && *(ptr + 2) == 0 && *(ptr + 3) == 0) {
            DEBUG_LEVEL(DBG_PACKET, "Bad tcp SACK option\n");
            LOG_BAD_PKT(p, "Bad tcp SACK option");
            return -1;
        }

        switch (type) {
        case TCP_OPT_MSS:
            p->tcp_mss = ntohs(*(uint16_t *)(ptr + 2));
            break;
        case TCP_OPT_WSCALE:
            p->tcp_wscale = *(ptr + 2);
            break;
        case TCP_OPT_TIMESTAMP:
            p->tcp_ts_value = ntohl(*(uint32_t *)(ptr + 2));
            p->tcp_ts_echo = ntohl(*(uint32_t *)(ptr + 6));
            p->flags |= DPI_PKT_FLAG_TCP_TS;
            break;
        case TCP_OPT_SACKOK:
            p->flags |= DPI_PKT_FLAG_SACKOK;
            break;
        }

        ptr += len;
    }

    return 0;
}

#define TCP_FLAG_MASK (TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN | TH_RST)
static uint8_t tcp_bad_flag_list[] = {
    0,
    TH_URG,
    TH_FIN,
    TH_PUSH,
    TH_PUSH | TH_FIN,
    TH_PUSH | TH_URG,
    TH_SYN | TH_FIN,
    TH_PUSH | TH_URG | TH_FIN,
    TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN,
    TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN | TH_RST,
};
BITMASK_DEFINE(tcp_bad_flag_mask, 256);

char *get_tcp_flag_string(struct tcphdr *tcph, char *s)
{
    char *f = s;

    *f ++ = tcph->urg ? 'U' : '*';
    *f ++ = tcph->ack ? 'A' : '*';
    *f ++ = tcph->psh ? 'P' : '*';
    *f ++ = tcph->rst ? 'R' : '*';
    *f ++ = tcph->syn ? 'S' : '*';
    *f ++ = tcph->fin ? 'F' : '*';
    *f = '\0';

    return s;
}

static int dpi_parse_tcp(dpi_packet_t *p)
{
    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
    uint16_t tcp_len = p->len - p->l4;
    uint16_t tcph_len;

    if (tcp_len < sizeof(*tcph)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad tcp packet length %u\n", tcp_len);
        LOG_BAD_PKT(p, "Bad tcp packet length %u", tcp_len);
        return -1;
    }

    tcph_len = get_tcph_len(tcph);
    if (tcph_len < sizeof(*tcph) || tcp_len < tcph_len) {
        DEBUG_LEVEL(DBG_PACKET, "Bad tcp header length: tcp_len=%u tcph_len=%u\n",
                                tcp_len, tcph_len);
        LOG_BAD_PKT(p, "Bad tcp header length: tcp_len=%u tcph_len=%u", tcp_len, tcph_len);
        return -1;
    }

    if (BITMASK_TEST(tcp_bad_flag_mask, tcph->th_flags & TCP_FLAG_MASK)) {
        char flags[10];
        DEBUG_LEVEL(DBG_PACKET, "Bad tcp flags %s\n", get_tcp_flag_string(tcph, flags));
        LOG_BAD_PKT(p, "Bad tcp flags %s", get_tcp_flag_string(tcph, flags));
        return -1;
    }

    // Checksum
    if (unlikely(g_io_config->enable_cksum)) {
        uint16_t pkt_cksum, cksum;

        pkt_cksum = tcph->check;
        tcph->check = 0;
        if (dpi_is_ipv4(p)) {
            cksum = get_l4v4_cksum((struct iphdr *)(p->pkt + p->l3), tcph, tcp_len);
        } else {
            cksum = get_l4v6_cksum((struct ip6_hdr *)(p->pkt + p->l3), IPPROTO_TCP,
                                   tcph, tcp_len);
        }
        tcph->check = pkt_cksum;
 
        if (pkt_cksum == 0xffff) {
            pkt_cksum = 0;
        }

        if (pkt_cksum != cksum) {
            DEBUG_LEVEL(DBG_PACKET, "Bad tcp checksum 0x%x, should be 0x%x\n",
                                    htons(pkt_cksum), htons(cksum));
            tcph->check = cksum; 
        }
    }

    if (tcph_len > sizeof(*tcph)) {
        if (dpi_parse_tcp_options(p) < 0) {
            return -1;
        }

        // Check TCP TS option can't be 0 for non-SYN packet
        if ((p->flags & DPI_PKT_FLAG_TCP_TS) &&
            p->tcp_ts_value == 0 && p->tcp_ts_echo ==0 &&
            tcph->ack && !tcph->syn) {
            DEBUG_LEVEL(DBG_PACKET, "Bad tcp zero timestamp\n");
            LOG_BAD_PKT(p, "Bad tcp zero timestamp");
            return -1;
        }

#define DPI_MIN_TCP_MSS 256
        if (p->tcp_mss > 0 && p->tcp_mss < DPI_MIN_TCP_MSS) {
            DEBUG_LEVEL(DBG_PACKET, "Small TCP MSS, mss=%u (<%u)\n", p->tcp_mss, DPI_MIN_TCP_MSS);
            dpi_threat_trigger(DPI_THRT_TCP_SMALL_MSS, p, "mss=%u (<%u)", p->tcp_mss, DPI_MIN_TCP_MSS);
        }
    }

    p->sport = ntohs(tcph->th_sport);
    p->dport = ntohs(tcph->th_dport);
    p->raw.ptr = p->pkt + p->l4 + tcph_len;
    p->raw.len = p->len - p->l4 - tcph_len;
    p->raw.seq = ntohl(tcph->th_seq);

    return 0;
}


static int dpi_parse_ipv4_hdr(dpi_packet_t *p)
{
    struct iphdr *iph;
    uint16_t ip_caplen, ip_len, iph_len;

    ip_caplen = p->cap_len - sizeof(struct ethhdr);
    if (ip_caplen < sizeof(struct iphdr)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad ipv4 packet length %u\n", ip_caplen);
        LOG_BAD_PKT(p, "Bad ipv4 packet length %u", ip_caplen);
        return -1;
    }

    iph = (struct iphdr *)(p->pkt + sizeof(struct ethhdr));

    if (iph->version != 4) {
        DEBUG_LEVEL(DBG_PACKET, "Bad ip version %u\n", iph->version);
        LOG_BAD_PKT(p, "Bad ip version %u", iph->version);
        return -1;
    }

    ip_len = ntohs(iph->tot_len);
    iph_len = get_iph_len(iph);

    if (iph_len < sizeof(*iph) || ip_len < iph_len || ip_len > ip_caplen) {
        DEBUG_LEVEL(DBG_PACKET,
                    "Bad ipv4 header length: ip_len=%u, hdr_len=%u caplen=%u\n",
                    ip_len, iph_len, ip_caplen);
        LOG_BAD_PKT(p, "Bad ipv4 header length: ip_len=%u, hdr_len=%u caplen=%u\n",
                       ip_len, iph_len, ip_caplen);
        return -1;
    }

    p->len = ip_len + sizeof(struct ethhdr);
    p->l4 = p->l3 + iph_len;

    // Checksum
    if (unlikely(g_io_config->enable_cksum)) {
        uint16_t pkt_cksum, cksum;

        pkt_cksum = iph->check;
        iph->check = 0;
        cksum = get_ip_cksum(iph);
        iph->check = pkt_cksum;

        if (pkt_cksum == 0xffff) {
            pkt_cksum = 0;
        }

        if (pkt_cksum != cksum) {
            DEBUG_LEVEL(DBG_PACKET, "bad ip checksum 0x%x, should be 0x%x\n",
                                    htons(pkt_cksum), htons(cksum));
            return -1;
        }
    }

    return 0;
}

static int dpi_parse_ipv4(dpi_packet_t *p)
{
    if (dpi_parse_ipv4_hdr(p) < 0) {
        return -1;
    }

    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);

    // IP fragment
    if (ntohs(iph->frag_off) & (IP_OFFMASK | IP_MF)) {
        if (dpi_ip_defrag(p) < 0) {
            return -1;
        }
    }

    p->ip_proto = iph->protocol;

    // Start L4 parsing
    switch (p->ip_proto) {
    case IPPROTO_TCP:
        th_counter.tcp_pkts ++;
        return dpi_parse_tcp(p);
    case IPPROTO_UDP:
        th_counter.udp_pkts ++;
        return dpi_parse_udp(p);
    case IPPROTO_ICMP:
        th_counter.icmp_pkts ++;
        return dpi_parse_icmp(p);
    default:
        th_counter.other_pkts ++;
        p->raw.ptr = p->pkt + p->l4;
        p->raw.len = p->len - p->l4;
        p->raw.seq = 0;
        break;
    }

    return 0;
}


static int dpi_parse_ipv6_ext(dpi_packet_t *p, uint8_t *protocol)
{
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
    uint8_t type = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    uint8_t *ptr = (uint8_t *)(ip6h + 1);
    uint8_t *end = p->pkt + p->len;
    int ext_len;
    bool hopopts = false;

    while (ptr < end) {
        switch (type) {
        case IPPROTO_FRAGMENT:
            ext_len = 8;

            if (p->ip6_fragh == NULL) {
                p->ip6_fragh = (struct ip6_frag *)ptr;
            }
            break;
        case IPPROTO_AH:
            if (ptr + 1 >= end) {
                return -1;
            }
            ext_len = (*(ptr + 1) + 2) << 2;
            break;
        case IPPROTO_HOPOPTS:
            if (hopopts) {
                return -1;
            }
            hopopts = true;
            // fall through
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
            if (ptr + 1 >= end) {
                return -1;
            }
            ext_len = (*(ptr + 1) + 1) << 3;
            break;
        case IPPROTO_NONE:
        default:
            *protocol = type;
            return ptr - (uint8_t *)ip6h;
        }

        if (ext_len <= 2) {
            return -1;
        }

        type = *ptr;
        ptr += ext_len;
    }

    return -1;
}

static int dpi_parse_ipv6_hdr(dpi_packet_t *p, uint8_t *protocol)
{
    struct ip6_hdr *ip6h;
    uint16_t ip6_caplen, ip6_len;
    int offset;

    ip6_caplen = p->cap_len - sizeof(struct ethhdr);
    if (ip6_caplen < sizeof(struct ip6_hdr)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad ipv6 packet length %u\n", ip6_caplen);
        LOG_BAD_PKT(p, "Bad ipv6 packet length %u", ip6_caplen);
        return -1;
    }

    ip6h = (struct ip6_hdr *)(p->pkt + sizeof(struct ethhdr));
    ip6_len = ntohs(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);

    if (ip6_len > ip6_caplen) {
        DEBUG_LEVEL(DBG_PACKET,
                    "Bad ipv6 header length: ip6_len=%u, caplen=%u\n",
                    ip6_len, ip6_caplen);
        LOG_BAD_PKT(p, "Bad ipv6 header length: ip6_len=%u, caplen=%u", ip6_len, ip6_caplen);
        return -1;
    }

    p->len = ip6_len + sizeof(struct ethhdr);

    offset = dpi_parse_ipv6_ext(p, protocol);
    if (offset < 0) {
        DEBUG_LEVEL(DBG_PACKET, "Bad ipv6 ext header\n");
        LOG_BAD_PKT(p, "Bad ipv6 ext header");
        return -1;
    }

    p->l4 = p->l3 + offset;

    return 0;
}


static int dpi_parse_ipv6(dpi_packet_t *p)
{
    uint8_t protocol = 0;

    if (dpi_parse_ipv6_hdr(p, &protocol) < 0) {
        return -1;
    }

    if (p->ip6_fragh != NULL) {
        if (dpi_ipv6_defrag(p) < 0) {
            return -1;
        }
    }

    p->ip_proto = protocol;

    // Start L4 parsing
    switch (p->ip_proto) {
    case IPPROTO_TCP:
        th_counter.tcp_pkts ++;
        return dpi_parse_tcp(p);
    case IPPROTO_UDP:
        th_counter.udp_pkts ++;
        return dpi_parse_udp(p);
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        th_counter.icmp_pkts ++;
        return dpi_parse_icmpv6(p);
    default:
        th_counter.other_pkts ++;
        p->raw.ptr = p->pkt + p->l4;
        p->raw.len = p->len - p->l4;
        p->raw.seq = 0;
        break;
    }

    return 0;
}

static int dpi_parse_packet(dpi_packet_t *p)
{
    struct ethhdr *eth;

    if (p->cap_len < sizeof(*eth)) {
        DEBUG_LEVEL(DBG_PACKET, "Bad ethernet header length %u\n", p->cap_len);
        LOG_BAD_PKT(p, "Bad ethernet header length %u", p->cap_len);
        return -1;
    }

    p->l2 = 0;
    p->l3 = sizeof(*eth);
    p->len = p->cap_len;

    eth = (struct ethhdr *)(p->pkt + p->l2);

    // Start L3 parsing
    p->eth_type = ntohs(eth->h_proto);
    switch (p->eth_type) {
    case ETH_P_IP:
        th_counter.ipv4_pkts ++;
        if (dpi_parse_ipv4(p) < 0) {
            return -1;
        }
        break;
    case ETH_P_IPV6:
        th_counter.ipv6_pkts ++;
        if (dpi_parse_ipv6(p) < 0) {
            return -1;
        }
        break;
    default:
        break;
    }

    return 0;
}

void dpi_set_action(dpi_packet_t *p, int act)
{
    if (p->action > DPI_ACTION_ALLOW && act <= DPI_ACTION_ALLOW) {
        return;
    }

    p->action = act;
    DEBUG_LOG(DBG_PACKET, p, "action=%s\n", debug_action_name(act));
}

bool dpi_is_action_final(dpi_packet_t *p, int act)
{
    if (unlikely(act == DPI_ACTION_BYPASS)) {
        return true;
    }
    if (p->ep->tap) {
        return false;
    }
    if (unlikely(act > DPI_ACTION_ALLOW)) {
        return true;
    }
    return false;
}

int dpi_parse_ethernet(dpi_packet_t *p)
{
    int ret;

    th_counter.pkt_id ++;
    p->id = th_counter.pkt_id;

    ret = dpi_parse_packet(p);
    if (ret < 0) {
        th_counter.err_pkts ++;
        dpi_set_action(p, DPI_ACTION_DROP);
        return p->action;
    }

    return DPI_ACTION_NONE;
}

static void dpi_pkt_proto_tracker(dpi_packet_t *p)
{
    switch (p->ip_proto) {
    case IPPROTO_TCP:
        // If session action is set, not to do TCP assembly but TCP state
        // transition still has to be done.
        dpi_tcp_tracker(p);
        if (unlikely(p->session == NULL)) {
            th_counter.tcp_nosess_pkts ++;
        }
        break;
    case IPPROTO_UDP:
        dpi_udp_tracker(p);
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        dpi_icmp_tracker(p);
        break;
    default:
        dpi_ip_tracker(p);
        break;
    }

}

// caller makes sure p->session is not NULL
static void dpi_pkt_proto_parser(dpi_packet_t *p)
{
    // Protocol parsers
    dpi_session_t *s = p->session;
    if (likely(!(s->flags & DPI_SESS_FLAG_SKIP_PARSER))) {
        if (unlikely(p->flags & DPI_PKT_FLAG_NEW_SESSION)) {
            if (s->flags & DPI_SESS_FLAG_MID_STREAM) {
                    dpi_midstream_recruit_parser(p);
            } else {
                    dpi_recruit_parser(p);
            }
        }

        if (!(p->flags & DPI_PKT_FLAG_SKIP_PARSER) && p->raw.len > 0) {
            if (s->flags & DPI_SESS_FLAG_MID_STREAM) {
                dpi_midstream_proto_praser(p);
            } else {
                dpi_proto_parser(p);
            }
        }
    }
}


// caller makes sure p->session is not NULL
static void dpi_pkt_policy_reeval(dpi_packet_t *p)
{
    bool to_server = dpi_is_client_pkt(p);
    dpi_session_t *s = p->session;
    int log_violate = 0;

    if (unlikely(dpi_policy_reeval(p, to_server) >= 1)) {
        log_violate = DPI_POLICY_LOG_VIOLATE(s->policy_desc.action);
        if (log_violate == 1) {
            FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_VIOLATE);
        }
        log_violate = DPI_POLICY_LOG_VIOLATE(s->xff_desc.action);
        if (log_violate == 1) {
            FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_XFF_VIO);
        }
        if (s->policy_desc.action == DP_POLICY_ACTION_DENY ||
            s->xff_desc.action == DP_POLICY_ACTION_DENY) {
            if (p->ip_proto == IPPROTO_TCP) {
                dpi_inject_reset(p, true);
                dpi_inject_reset(p, false);
            }
            // For mid session deny, keep the session to block
            // traffic coming afterwards
            //dpi_session_delete(s, DPI_SESS_TERM_POLICY);
            //p->session = NULL;
            p->session->action = DPI_ACTION_BLOCK;
            dpi_set_action(p, DPI_ACTION_DROP);
        }
    }
}

static void dpi_pkt_log(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    if (!s) {
        return;
    }

    if (likely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_SURE_PARSER))) {
        // Generate session log when app type becomes 'sure'
        if (unlikely(FLAGS_TEST(s->flags, DPI_SESS_FLAG_START_LOGGED) == 0)) {
            // Not to log ping scan
            if ((p->ip_proto == IPPROTO_ICMP || p->ip_proto == IPPROTO_ICMPV6) && s->server.pkts == 0) {
                return;
            }
            // proxymesh related session
            if (cmp_mac_prefix(p->ep_mac,PROXYMESH_MAC_PREFIX) && 
                /* 1. send connection report only when  return packet from server is seen */
                ((!FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS) && s->server.pkts == 0) //||
                /* 2. not to send connection report for session whose client and server ip are both 127.0.0.1/::1 */
                 /*(FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS) && s->server.ip.ip4 == s->client.ip.ip4 && s->server.ip.ip4 == htonl(INADDR_LOOPBACK)) ||
                 (FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS) && (memcmp((uint8_t *)&s->server.ip, (uint8_t *)&s->client.ip, sizeof(s->server.ip)) == 0) && 
                  (memcmp((uint8_t *)&s->server.ip, (uint8_t *)(in6addr_loopback.s6_addr), sizeof(s->server.ip)) == 0))*/)){
                return;
            }
            if (likely(dpi_session_start_log(s, false) == 0)) {
                FLAGS_SET(s->flags, DPI_SESS_FLAG_START_LOGGED);
                if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_LOG_XFF))) {
                    dpi_session_start_log(s, true);
                }
            }
        } else if (unlikely(FLAGS_TEST(p->flags, (DPI_PKT_FLAG_LOG_MID|DPI_PKT_FLAG_LOG_VIOLATE|DPI_PKT_FLAG_LOG_XFF|DPI_PKT_FLAG_LOG_XFF_VIO)) ||
                            (th_snap.tick - s->last_report >= DPI_CONNECT_REPORT_INTERVAL) ||
                            // Report UDP DNS more often to trigger iodine tunnel detection.
                            // Normal DNS sessions are short.
                            (s->ip_proto == IPPROTO_UDP && s->only_parser == DPI_PARSER_DNS &&
                             th_snap.tick - s->last_report >= DPI_CONNECT_REPORT_INTERVAL_SHORT))) {
            if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_LOG_XFF))) {
                if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_LOG_MID))) {
                    dpi_session_mid_log(s, (p->flags & DPI_PKT_FLAG_LOG_VIOLATE) ? 1 : 0, false);
                }
                dpi_session_mid_log(s, (p->flags & DPI_PKT_FLAG_LOG_XFF_VIO) ? 1 : 0, true);
            } else {
                dpi_session_mid_log(s, (p->flags & DPI_PKT_FLAG_LOG_VIOLATE) ? 1 : 0, false);
            }
        }
    }
    return;
}

static void dpi_post_cache_packet(dpi_packet_t *p)
{
    dpi_wing_t *w0 = p->this_wing;

    if ((p->session->flags & DPI_SESS_FLAG_SKIP_PARSER) || p->ip_proto != IPPROTO_TCP) {
        w0->asm_seq = w0->next_seq;
    }

    asm_flush(&w0->asm_cache, w0->asm_seq, dpi_asm_remove);

    if (!(p->flags & DPI_PKT_FLAG_CACHED) &&
        p->ip_proto == IPPROTO_TCP && p->raw.len > 0 &&
        u32_gt(p->raw.seq + p->raw.len, w0->asm_seq)) {
        dpi_cache_packet(p, w0, true);

        // Packet loss is high under load, tcp_tracker() could exit early before calling
        // dpi_cache_packet, for example, if the packet is out-of-window; then asm_seq
        // is not updated, we end of keep caching the packet here. ===>
        // Ignore if cache size is overrun.
        if (asm_gross(&w0->asm_cache) > DPI_MAX_PKT_LEN) {
            DEBUG_LOG(DBG_TCP, p, "Cache overrun, flush!\n");

            dpi_set_action(p, DPI_ACTION_BYPASS);
            asm_destroy(&w0->asm_cache, dpi_asm_remove);
            asm_destroy(&p->that_wing->asm_cache, dpi_asm_remove);
        }
    }

    // debug_dump_session(p->session);
    DEBUG_LOG(DBG_PACKET, p, "ASM cache, seq=0x%x pkts=%u gross=%u\n",
              w0->asm_seq, asm_count(&w0->asm_cache), asm_gross(&w0->asm_cache));
}

int dpi_inspect_ethernet(dpi_packet_t *p)
{
    p->pkt_buffer = &p->raw;

    // Session lookup
    p->session = dpi_session_lookup(&th_packet);

    if (p->session != NULL) {
        dpi_session_t *sess = p->session;

        p->this_wing->pkts ++;
        p->this_wing->bytes += p->cap_len;

        if (p->ep->tap) {
           FLAGS_SET(sess->flags, DPI_SESS_FLAG_TAP);
        } else {
           FLAGS_UNSET(sess->flags, DPI_SESS_FLAG_TAP);
        }
        if (cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX)){
           FLAGS_SET(sess->flags, DPI_SESS_FLAG_PROXYMESH);
        } else {
           FLAGS_UNSET(sess->flags, DPI_SESS_FLAG_PROXYMESH);
        }
    }

    dpi_pkt_proto_tracker(p);

    if (p->session != NULL) {
        dpi_session_t *sess = p->session;

        if (unlikely(p->severity > sess->severity)) {
            // Populate severity of threat detected.
            sess->severity = p->severity;
            sess->threat_id = p->threat_id;
            FLAGS_SET(p->flags, DPI_PKT_FLAG_LOG_MID);
        }
        // Copy session action to the packet if packet action is allow.
        dpi_set_action(p, sess->action);

        if (p->action == DPI_ACTION_BYPASS) {
            dpi_pkt_policy_reeval(p);
        } else if (p->ep->tap || p->action <= DPI_ACTION_ALLOW) {
            dpi_pkt_proto_parser(p);
            dpi_pkt_policy_reeval(p);
        }
    }

    bool dlp_detect = dpi_dlp_ep_policy_check(p);
    if (dlp_detect) {
        p->flags |= DPI_PKT_FLAG_DETECT_DLP;
    }
    bool waf_detect = dpi_waf_ep_policy_check(p);
    if (waf_detect) {
        p->flags |= DPI_PKT_FLAG_DETECT_WAF;
    }

    // pattern match
    if ((dlp_detect || waf_detect) && ((p->session == NULL ||
                  !FLAGS_TEST(p->session->flags, DPI_SESS_FLAG_IGNOR_PATTERN)) &&
        !FLAGS_TEST(p->flags, DPI_PKT_FLAG_SKIP_PATTERN))){

        bool continue_detect = true;

        // match reassmebled packet first
        if (continue_detect && FLAGS_TEST(p->flags, DPI_PKT_FLAG_ASSEMBLED)) {
            p->pkt_buffer = &p->asm_pkt;

            if (p->pkt_buffer->len > 0) {
                continue_detect = dpi_process_detector(p);
            }
            p->pkt_buffer = &p->raw;

        }

        //match decoded data        
        if (continue_detect && p->decoded_pkt.len > 0) {
            p->pkt_buffer = &p->decoded_pkt;

            if (p->pkt_buffer->len > 0) {
                continue_detect = dpi_process_detector(p);
            }
            p->pkt_buffer = &p->raw;
        }

        if (continue_detect) {
            if (p->pkt_buffer->len > 0) {
                continue_detect = dpi_process_detector(p);
            }
        }

        if (p->session != NULL && !continue_detect) {
            FLAGS_SET(p->session->flags, DPI_SESS_FLAG_IGNOR_PATTERN);
        }
    }

    dpi_pkt_log(p);

    if (likely(!dpi_is_action_final(p, p->action) && p->session != NULL)) {
        dpi_post_cache_packet(p);
    }

    // Convert packet action to session action
    // Drop or Block is marked by detection, should not trigger in monitoring mode;
    // Bypass is marked because we want to skip the session intentionally, so session should be marked.
    if (unlikely(p->action != DPI_ACTION_NONE)) {
        if (p->ep->tap) {
            if (p->session != NULL && p->action == DPI_ACTION_BYPASS) {
                p->session->action = DPI_ACTION_BYPASS;
            }
        } else {
            switch (p->action) {
            case DPI_ACTION_ALLOW:
                break;
            case DPI_ACTION_DROP:
                if (likely(p->ip_proto == IPPROTO_TCP && p->session != NULL)) {
                    p->session->action = DPI_ACTION_BLOCK;
                }
                break;
            case DPI_ACTION_RESET:
                if (likely(p->ip_proto == IPPROTO_TCP && p->session != NULL)) {
                    p->session->action = DPI_ACTION_BLOCK;
                    dpi_inject_reset(p, true);
                    dpi_inject_reset(p, false);
                }
                break;
            case DPI_ACTION_BYPASS:
                if (likely(p->session != NULL)) {
                    p->session->action = DPI_ACTION_BYPASS;
                }
                p->action = DPI_ACTION_ALLOW;
                break;
            case DPI_ACTION_BLOCK:
                if (likely(p->session != NULL)) {
                    p->session->action = DPI_ACTION_BLOCK;
                }
                p->action = DPI_ACTION_DROP;
                break;
            }
        }
    }

    return p->action;
}

void dpi_catch_stats_slot(io_stats_t *stats, uint32_t slot)
{
    if (slot - stats->cur_slot >= STATS_SLOTS) {
        memset(&stats->in.sess_ring, 0, sizeof(stats->in.sess_ring));
        memset(&stats->out.sess_ring, 0, sizeof(stats->out.sess_ring));
        memset(&stats->in.pkt_ring, 0, sizeof(stats->in.pkt_ring));
        memset(&stats->out.pkt_ring, 0, sizeof(stats->out.pkt_ring));
        memset(&stats->in.byte_ring, 0, sizeof(stats->in.byte_ring));
        memset(&stats->out.byte_ring, 0, sizeof(stats->out.byte_ring));
        stats->cur_slot = slot;
    } else {
        uint32_t s;
        for (; stats->cur_slot < slot; stats->cur_slot ++) {
            s = (stats->cur_slot + 1) % STATS_SLOTS;
            stats->in.sess_ring[s] = 0;
            stats->out.sess_ring[s] = 0;
            stats->in.pkt_ring[s] = 0;
            stats->out.pkt_ring[s] = 0;
            stats->in.byte_ring[s] = 0;
            stats->out.byte_ring[s] = 0;
        }
    }
}

void dpi_inc_stats_packet(dpi_packet_t *p)
{
    uint32_t s = p->ep_stats->cur_slot % STATS_SLOTS;
    p->ep_all_metry->packet ++;
    p->ep_all_metry->pkt_ring[s] ++;
    p->ep_all_metry->byte += p->cap_len;
    p->ep_all_metry->byte_ring[s] += p->cap_len;

    p->all_metry->packet ++;
    p->all_metry->pkt_ring[s] ++;
    p->all_metry->byte += p->cap_len;
    p->all_metry->byte_ring[s] += p->cap_len;
}

void dpi_inc_stats_session(dpi_packet_t *p, dpi_session_t *s)
{
    uint32_t slot = p->ep_stats->cur_slot % STATS_SLOTS;

    if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS)) {
        th_stats.in.session ++;
        th_stats.in.cur_session ++;
        th_stats.in.sess_ring[slot] ++;

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, s->server.mac);
        if (mac != NULL) {
            mac->ep->stats.in.session ++;
            mac->ep->stats.in.cur_session ++;
            mac->ep->stats.in.sess_ring[slot] ++;
        }
    } else {
        th_stats.out.session ++;
        th_stats.out.cur_session ++;
        th_stats.out.sess_ring[slot] ++;

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, s->client.mac);
        if (mac != NULL) {
            mac->ep->stats.out.session ++;
            mac->ep->stats.out.cur_session ++;
            mac->ep->stats.out.sess_ring[slot] ++;
        }
    }
}

void dpi_dec_stats_session(dpi_session_t *s)
{
    if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS)) {
        th_stats.in.cur_session --;

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, s->server.mac);
        if (mac != NULL) {
            mac->ep->stats.in.cur_session --;
        }
    } else {
        th_stats.out.cur_session --;

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, s->client.mac);
        if (mac != NULL) {
            mac->ep->stats.out.cur_session --;
        }
    }
}

void dpi_packet_setup(void)
{
    int i;

    for (i = 0; i < ARRAY_ENTRIES(tcp_bad_flag_list); i ++) {
        BITMASK_SET(tcp_bad_flag_mask, tcp_bad_flag_list[i]);
    }
}
