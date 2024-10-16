#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "dpi/dpi_module.h"

bool debug_log_packet_filter(const dpi_packet_t *p)
{
    if (p == NULL) return true;

    return true;
}

bool debug_log_session_filter(const dpi_session_t *s)
{
    if (s == NULL) return true;

    return true;
}

void debug_log(bool print_ts, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    g_io_callback->debug(print_ts, fmt, args);
    va_end(args);
}

//debug purpose only not use in production
void debug_dump_hex(const uint8_t *ptr, int len)
{
#define LINE_LEN (6 + 3 + 16 * 3 + 6 + 16)
#define HEX_POS (6 + 3)
#define ASC_POS (6 + 3 + 16 * 3 + 6)
    char line[LINE_LEN + 1];
    int offset = 0, i;

    line[LINE_LEN] = '\0';
    for (offset = 0; offset < len; offset += 16) {
        memset(line, ' ', LINE_LEN);
        sprintf(line, "0x%04x", offset);
        line[6] = ' ';
        for (i = 0; i < 16; i ++) {
            if (offset + i < len) {
                uint8_t c = ptr[offset + i];
                sprintf(&line[HEX_POS + i * 3], "%02x", c);
                line[HEX_POS + i * 3 + 2] = ' ';
                if (isprint(c)) {
                    line[ASC_POS + i] = c;
                } else {
                    line[ASC_POS + i] = '.';
                }
            }
        }

        debug_log(false, "%s\n", line);
    }
}

static void dump_tcp_header(const dpi_packet_t *p)
{
    if (p->l4 == 0) return;

    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
    char flags[10];

    debug_log(false, "TCP payload:%ub header:%ub seq:0x%x ack:0x%x flags:%s\n",
              p->raw.len, get_tcph_len(tcph),
              ntohl(tcph->th_seq), ntohl(tcph->th_ack),
              get_tcp_flag_string(tcph, flags));
}

static void dump_udp_header(const dpi_packet_t *p)
{
    debug_log(false, "UDP payload:%ub\n", p->raw.len);
}

static void dump_icmp_header(const dpi_packet_t *p)
{
    if (p->l4 == 0) return;

    struct icmphdr *icmph = (struct icmphdr *)(p->pkt + p->l4);

    debug_log(false, "ICMP payload:%ub type:%u code:%u\n",
              p->raw.len, icmph->type, icmph->code);
}


static void dump_icmpv6_header(const dpi_packet_t *p)
{
    if (p->l4 == 0) return;

    struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)(p->pkt + p->l4);

    debug_log(false, "ICMPv6 payload:%ub type:%u code:%u\n",
              p->raw.len, icmp6h->icmp6_type, icmp6h->icmp6_code);
}

static void dump_ipv6_port(const dpi_packet_t *p)
{
    if (p->l3 == 0) return;
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);

    debug_log(false, "%u-", p->ip_proto);
    debug_log(false, DBG_IPV6_FORMAT, DBG_IPV6_TUPLE(ip6h->ip6_src));
    if (p->ip_proto == IPPROTO_TCP || p->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", p->sport);
    }
    debug_log(false, " -> "DBG_IPV6_FORMAT, DBG_IPV6_TUPLE(ip6h->ip6_dst));
    if (p->ip_proto == IPPROTO_TCP || p->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", p->dport);
    }
}

static void dump_ipv6_header(const dpi_packet_t *p)
{
    if (p->l3 == 0) return;
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);

    dump_ipv6_port(p);
    debug_log(false, " length:%u\n", ntohs(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen));
}

static void dump_ip_port(const dpi_packet_t *p)
{
    if (p->l3 == 0) return;
    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);

    debug_log(false, "%u-", p->ip_proto);
    debug_log(false, DBG_IPV4_FORMAT, DBG_IPV4_TUPLE(iph->saddr));
    if (p->ip_proto == IPPROTO_TCP || p->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", p->sport);
    }
    debug_log(false, " -> "DBG_IPV4_FORMAT, DBG_IPV4_TUPLE(iph->daddr));
    if (p->ip_proto == IPPROTO_TCP || p->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", p->dport);
    }
}

static void dump_ip_header(const dpi_packet_t *p)
{
    if (p->l3 == 0) return;

    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);

    dump_ip_port(p);
    debug_log(false, " length:%u id:%u\n", ntohs(iph->tot_len), ntohs(iph->id));
}

static void dump_eth_header(const dpi_packet_t *p)
{
    struct ethhdr *eth = (struct ethhdr *)(p->pkt + p->l2);

    debug_log(false, DBG_MAC_FORMAT" -> "DBG_MAC_FORMAT" type:0x%04x\n",
              DBG_MAC_TUPLE(eth->h_source), DBG_MAC_TUPLE(eth->h_dest),
              ntohs(eth->h_proto));
}

void debug_dump_packet_short(const dpi_packet_t *p)
{
    if (p->l3 == 0) return;

    switch (p->eth_type) {
    case ETH_P_IP:
        dump_ip_port(p);
        break;
    case ETH_P_IPV6:
        dump_ipv6_header(p);
        break;
    default:
        return;
    }
    debug_log(false, "\n");
}

void debug_dump_packet(const dpi_packet_t *p)
{
    debug_log(true, "\nPACKET id:%llu len:%u dir:%s\n", p->id, p->cap_len,
              (p->flags & DPI_PKT_FLAG_INGRESS) ? "ingress" : "egress");

    dump_eth_header(p);

    switch (p->eth_type) {
    case ETH_P_IP:
        dump_ip_header(p);
        break;
    case ETH_P_IPV6:
        dump_ipv6_header(p);
        break;
    default:
        return;
    }

    switch (p->ip_proto) {
    case IPPROTO_TCP:
        dump_tcp_header(p);
        break;
    case IPPROTO_UDP:
        dump_udp_header(p);
        break;
    case IPPROTO_ICMP:
        dump_icmp_header(p);
        break;
    case IPPROTO_ICMPV6:
        dump_icmpv6_header(p);
        break;
    }
}

static void dump_ip_session(const dpi_session_t *s)
{
    debug_log(false, "%u-", s->ip_proto);
    debug_log(false, DBG_IPV4_FORMAT, DBG_IPV4_TUPLE(s->client.ip.ip4));
    if (s->ip_proto == IPPROTO_TCP || s->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", s->client.port);
    }
    debug_log(false, " -> "DBG_IPV4_FORMAT, DBG_IPV4_TUPLE(s->server.ip.ip4));
    if (s->ip_proto == IPPROTO_TCP || s->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", s->server.port);
    }
}

static void dump_ipv6_session(const dpi_session_t *s)
{
    debug_log(false, "%u-", s->ip_proto);
    debug_log(false, DBG_IPV6_FORMAT, DBG_IPV6_TUPLE(s->client.ip.ip6));
    if (s->ip_proto == IPPROTO_TCP || s->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", s->client.port);
    }
    debug_log(false, " -> "DBG_IPV6_FORMAT, DBG_IPV6_TUPLE(s->server.ip.ip6));
    if (s->ip_proto == IPPROTO_TCP || s->ip_proto == IPPROTO_UDP) {
        debug_log(false, ":%u", s->server.port);
    }
}

void debug_dump_session_short(const dpi_session_t *s)
{
    if (s->flags & DPI_SESS_FLAG_IPV4) {
        dump_ip_session(s);
    } else {
        dump_ipv6_session(s);
    }
    debug_log(false, "\n");
}

void debug_dump_session(const dpi_session_t *s)
{
    if (!debug_log_session_filter(s)) {
        return;
    }

    debug_log(true, "\nSESSION id:%llu\n", s->id);
    if (s->flags & DPI_SESS_FLAG_IPV4) {
        dump_ip_session(s);
    } else {
        dump_ipv6_session(s);
    }
    debug_log(false, "\n");

    debug_log(true, "count: %u/%u %s -> %u/%u %s age:%u\n",
              s->client.pkts, dpi_wing_length(&s->client),
              s->ip_proto == IPPROTO_TCP ? dpi_get_tcp_state_name(s->client.tcp_state) : "",
              s->server.pkts, dpi_wing_length(&s->server),
              s->ip_proto == IPPROTO_TCP ? dpi_get_tcp_state_name(s->server.tcp_state) : "",
              th_snap.tick - s->created_at);
}
