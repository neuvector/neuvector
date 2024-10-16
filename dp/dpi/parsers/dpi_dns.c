#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define MAX_LABEL_LEN  256
#define MAX_RECORD_NUM 256
typedef struct dns_wing_ {
    uint32_t seq;
} dns_wing_t;

typedef struct dns_data_ {
    dns_wing_t client, server;
} dns_data_t;

typedef struct dns_question_ {
    char question[MAX_LABEL_LEN];
} dns_question_t;

typedef struct dns_answer_ {
    bool ip;
    char question[MAX_LABEL_LEN];
    union {
        uint32_t ip4;
        char cname[MAX_LABEL_LEN];
    };
} dns_answer_t;

#define DNS_OP_QUERY    0       // Standard query
#define DNS_OP_IQUERY   1       // Inverse query (deprecated/unsupported)
#define DNS_OP_STATUS   2       // Name server status query (unsupported)
#define DNS_OP_NOTIFY   4       // Zone change notification
#define DNS_OP_UPDATE   5       // Zone update message

#define DNS_TYPE_INVALID  0     // Cookie
#define DNS_TYPE_A        1     // Host address
#define DNS_TYPE_NS       2     // Authoritative server
#define DNS_TYPE_MD       3     // Mail destination
#define DNS_TYPE_MF       4     // Mail forwarder
#define DNS_TYPE_CNAME    5     // Canonical name
#define DNS_TYPE_SOA      6     // Start of authority zone
#define DNS_TYPE_MB       7     // Mailbox domain name
#define DNS_TYPE_MG       8     // Mail group member
#define DNS_TYPE_MR       9     // Mail rename name
#define DNS_TYPE_NULL     10    // Null resource record
#define DNS_TYPE_WKS      11    // Well known service
#define DNS_TYPE_PTR      12    // Domain name pointer
#define DNS_TYPE_HINFO    13    // Host information
#define DNS_TYPE_MINFO    14    // Mailbox information
#define DNS_TYPE_MX       15    // Mail routing information
#define DNS_TYPE_TXT      16    // Text strings
#define DNS_TYPE_RP       17    // Responsible person
#define DNS_TYPE_AFSDB    18    // AFS cell database
#define DNS_TYPE_X25      19    // X_25 calling address
#define DNS_TYPE_ISDN     20    // ISDN calling address
#define DNS_TYPE_RT       21    // Router
#define DNS_TYPE_NSAP     22    // NSAP address
#define DNS_TYPE_NSAP_PTR 23    // Reverse NSAP lookup (deprecated)
#define DNS_TYPE_SIG      24    // Threat signature
#define DNS_TYPE_KEY      25    // Threat key
#define DNS_TYPE_PX       26    // X.400 mail mapping
#define DNS_TYPE_GPOS     27    // Geographical position (withdrawn)
#define DNS_TYPE_AAAA     28    // Ip6 Address
#define DNS_TYPE_LOC      29    // Location Information
#define DNS_TYPE_NXT      30    // Next domain (threat)
#define DNS_TYPE_EID      31    // Endpoint identifier
#define DNS_TYPE_NIMLOC   32    // Nimrod Locator
#define DNS_TYPE_SRV      33    // Server Selection
#define DNS_TYPE_ATMA     34    // ATM Address
#define DNS_TYPE_NAPTR    35    // Naming Authority PoinTeR
#define DNS_TYPE_KX       36    // Key Exchange
#define DNS_TYPE_CERT     37    // Certification record
#define DNS_TYPE_A6       38    // IPv6 address (deprecates AAAA)
#define DNS_TYPE_DNAME    39    // Non-terminal DNAME (for IPv6)
#define DNS_TYPE_SINK     40    // Kitchen sink (experimentatl)
#define DNS_TYPE_OPT      41    // EDNS0 option (meta-RR)
#define DNS_TYPE_APL      42    // APL. RFC 3123
#define DNS_TYPE_DSIG     43    // Delegation signature. RFC 3658
#define DNS_TYPE_SSH      44    // SSH Key Fingerprint. RFC 4255
#define DNS_TYPE_IPSECKEY 45    // IPSECKEY. RFC 3755
#define DNS_TYPE_RRSIG    46    // RRSIG
#define DNS_TYPE_NSEC     47    // NSEC, NextSECure
#define DNS_TYPE_DNSKEY   48    // DNSKEY
#define DNS_TYPE_DHCID    49    // DHCP identifier
#define DNS_TYPE_NSEC3    50    // NSEC3. RFC 5155
#define DNS_TYPE_NSEC3P   51    // NSEC3PARAM. RFC 5155
#define DNS_TYPE_TLSA     52    // TLSA
#define DNS_TYPE_HIP      55    // HIP. RFC 5205
#define DNS_TYPE_NINFO    56    // NINFO
#define DNS_TYPE_RKEY     57    // RKEY
#define DNS_TYPE_TALINK   58    // TALINK. Trust Anchor LINK
#define DNS_TYPE_CHILDDS  59    // Child DS
#define DNS_TYPE_SPF      99    // SPF, Sender Policy Framework. RFC 4408
#define DNS_TYPE_UINFO    100
#define DNS_TYPE_UID      101
#define DNS_TYPE_GID      102
#define DNS_TYPE_UNSPEC   103
#define DNS_TYPE_TKEY     249   // RFC 2930
#define DNS_TYPE_TSIG     250   // Transaction Signature. RFC 2845, RFC 3645
#define DNS_TYPE_IXFR     251   // Incremental transfer. RFC 1995
#define DNS_TYPE_AXFR     252   // Transfer zone of authority. RFC 1035
#define DNS_TYPE_MAILB    253   // Transfer mailbox records RFC 1035
#define DNS_TYPE_MAILA    254   // Transfer mail agent records. Obsolete.  RFC 1035
#define DNS_TYPE_ANY      255   // Wildcard match

#define DNS_CLASS_INVALID  0    // Cookie
#define DNS_CLASS_IN       1    // Internet
#define DNS_CLASS_2        2    // Unallocated/unsupported
#define DNS_CLASS_CHAOS    3    // MIT Chaos-net
#define DNS_CLASS_HS       4    // MIT Hesiod
#define DNS_CLASS_NONE     254  // For prereq. sections in update request
#define DNS_CLASS_ANY      255  // Wildcard match

typedef struct dns_hdr_ {
    uint16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t rd     :1, // recursion desired
            tc     :1, // truncated message
            aa     :1, // authoritive answer
            opcode :4, // purpose of message
            qr     :1; // query/response flag
    uint8_t rcode  :4, // response code
            cd     :1, // checking disabled
            ad     :1, // authenticated data
            z      :1, // reserved
            ra     :1; // recursion available
#else
    uint8_t qr     :1, // query/response flag
            opcode :4, // purpose of message
            aa     :1, // authoritive answer
            tc     :1, // truncated message
            rd     :1; // recursion desired
    uint8_t ra     :1, // recursion available
            z      :1, // reserved
            ad     :1, // authenticated data
            cd     :1, // checking disabled
            rcode  :4; // response code
#endif
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} dns_hdr_t;

//get the dns domain name and canonical name, it is allowed pointer
static int get_dns_name(dpi_packet_t *p, uint8_t *ptr, int len, int shift, char *labels)
{
    int  size,total = 0;
    int  loop = 0;
    uint8_t *np = ptr + shift, *end = ptr + len;
    char *lp = labels;

    while(np > ptr && np < end){
        switch ((*np) & 0xc0) {
        case 0x0: //label
            size = *np;
            //check size valid
            if (size == 0) {
                if (lp > labels) {
                    *(lp-1)  = 0;
                } 
                if (loop == 0) {
                    total += 1;
                } 
                return total;
            }
            np++;
            if ((np+size) >= end) {
                DEBUG_LOG(DBG_PARSER, p, "invalid dns question label\n");
                return -1;
            }
            if ((lp+size) >= (labels+MAX_LABEL_LEN)) return -1;

            memcpy(lp, np, size);
            np  += size;
            lp  += size;
            *lp++  = '.';
            if (loop == 0) {
                total += size + 1;
            } 
            break;
        case 0xc0: //pointer
            size = (*np) & 0x3f;
            size = (size << 8) + *(np + 1);

            //check whether pointer moving out of bounce
            if (size >= len) {
                DEBUG_LOG(DBG_PARSER, p, "invalid dns pointer\n");
                return -1;
            }
            loop ++;
#define ALLOW_POINTER_NUMBER    63
            //to avoid loop forever
            if (loop > ALLOW_POINTER_NUMBER) { 
                DEBUG_LOG(DBG_PARSER, p, "dns pointer loop=%d\n", loop);
                dpi_threat_trigger(DPI_THRT_DNS_LOOP_PTR, p, "DNS pointer loop=%d", loop);
                return -1;
            }

            np  = ptr + size;
            //only count the first pointer shifted
            if (loop == 1) {
                total += 2;
            }
            break;
         case 0x40: // RFC 2673
            // 0                   1                   2
            // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2     . . .
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-//+-+-+-+-+-+-+
            // |0 1|    ELT    |     Count     |           Label ...         |
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+//-+-+-+-+-+-+-+
            if (len < 3) {
                // at least padded to 1 byte
                return -1;
            }
            // count is number bits, padded to byte
            size = *(np + 1);
            size = ((size - 1) << 3) + 1;
            if (len < size + 2) {
                DEBUG_LOG(DBG_PARSER, p, "DNS ext. label invalid length.\n");
                return -1;
            }
            return size + 2;
         case 0x80: // unknown type
         default:
            return -1;
        }
    }
    return -1;
}

//get the domain to ip mapping
static int get_domain_ip_mapping(dpi_packet_t *p, dns_question_t* questions, int qn, dns_answer_t* answers, int an)
{
    int i,j;
    for (i=0; i < qn; i++) {
        char name[MAX_LABEL_LEN];
        uint32_t ips[an];
        int cnt = 0;

        strlcpy(name, questions[i].question, MAX_LABEL_LEN);
        for (j=0; j < an; j++) {
            if (strcasecmp(name, answers[j].question) == 0) {
                if (answers[j].ip) {
                    //inform policy here
                    DEBUG_LOG(DBG_PARSER, p, "%s --> "DBG_IPV4_FORMAT"\n",questions[i].question,
                            DBG_IPV4_TUPLE(answers[j].ip4));
                    ips[cnt] = answers[j].ip4;
                    cnt++;
                } else {
                    strlcpy(name, answers[j].cname, MAX_LABEL_LEN);
                }
            }
        }
        if (cnt > 0) {
            snooped_fqdn_ipv4_mapping(questions[i].question, ips, cnt);
            sniff_ip_fqdn_storage(questions[i].question, ips, cnt);
        }
    }
    return 0;
}

static int dns_question(dpi_packet_t *p, uint8_t *ptr, int len, int shift, int count, dns_question_t *questions, int *qt_count)
{
    char labels[MAX_LABEL_LEN];
    while (count > 0) {
        labels[0] = 0;
        int jump = get_dns_name(p, ptr, len, shift, labels);
        if (jump < 0) {
            return jump;
        }

        shift += jump + 4;
        if (shift > len) return -1;

        uint16_t type = ntohs(*(uint16_t *)(ptr+shift-4));

        if (type == DNS_TYPE_A && questions != NULL) {
            if (jump > 1) {
                strlcpy(questions[(*qt_count)++].question, labels, MAX_LABEL_LEN);
            }
        }else if (type == DNS_TYPE_AXFR) {
            DEBUG_LOG(DBG_PARSER, p, "DNS Zone Transfer AXFR.\n");
            dpi_threat_trigger(DPI_THRT_DNS_ZONE_TRANSFER, p, "DNS Zone Transfer AXFR");
        }else if (type == DNS_TYPE_IXFR) {
            DEBUG_LOG(DBG_PARSER, p, "DNS Zone Transfer IXFR.\n");
            dpi_threat_trigger(DPI_THRT_DNS_ZONE_TRANSFER, p, "DNS Zone Transfer IXFR");
        }else if (type == DNS_TYPE_NULL) {
            DEBUG_LOG(DBG_PARSER, p, "DNS NULL type.\n");
            dpi_threat_trigger(DPI_THRT_DNS_TYPE_NULL, p, "DNS NULL type");
        }
        count --;
    }

    return shift;
}

static int dns_answer(dpi_packet_t *p, uint8_t *ptr, int len, int shift, int count, dns_answer_t *answers, int *aw_count)
{
    char labels[MAX_LABEL_LEN];
    while (count > 0) {
        labels[0] = 0;
        int jump = get_dns_name(p, ptr, len, shift, labels);
        if (jump < 0) {
            return jump;
        }
        shift += jump;

        if (shift + 10 > len) {
            DEBUG_LOG(DBG_PARSER, p, "DNS record not long enough.\n");
            return -1;
        }

        uint16_t type = ntohs(*(uint16_t *)(ptr + shift));
        uint16_t rd_len = ntohs(*(uint16_t *)(ptr + shift + 8));
        shift += 10;

        if (shift + rd_len > len) {
            DEBUG_LOG(DBG_PARSER, p, "DNS Rdata too long.rdata=%d\n",rd_len);
            return -1;
        }

        //ipv4 address
        if (type == DNS_TYPE_A && rd_len == 4 && answers != NULL) {
            if (jump > 1) {
                strlcpy(answers[*aw_count].question, labels, MAX_LABEL_LEN);
                uint8_t *addr = ptr + shift;
                memcpy(&answers[*aw_count].ip4, addr, 4);
                answers[*aw_count].ip = true;
                (*aw_count)++;
            }
        }else if (type == DNS_TYPE_CNAME && answers != NULL) {
            char cname[MAX_LABEL_LEN]={'\0'};
            if (jump > 1) {
                int ret = get_dns_name(p, ptr, len, shift, cname);
                if (ret > 1) {
                    strlcpy(answers[*aw_count].question, labels, MAX_LABEL_LEN);
                    strlcpy(answers[*aw_count].cname, cname, MAX_LABEL_LEN);
                    answers[*aw_count].ip = false;
                    (*aw_count)++;
                }
            }
        }
        shift += rd_len;
        count --;
    }

    return shift;
}

static int dns_parser(dpi_packet_t *p, uint8_t *ptr, uint32_t len)
{
    int shift = 0;
    dns_hdr_t *dns = (dns_hdr_t *)ptr;
    dns_question_t* questions = NULL;
    dns_answer_t* answers = NULL;
    int qt_count = 0, aw_count = 0;


    switch (dns->opcode) {
    case DNS_OP_QUERY:
    case DNS_OP_IQUERY:
    case DNS_OP_STATUS:
    case DNS_OP_NOTIFY:
    case DNS_OP_UPDATE:
        break;
    default:
        return -1;
    }

    DEBUG_LOG(DBG_PARSER, p, "Opcode: %d\n", dns->opcode);

    // Question must have question records and no answer record
    // if opcode type == DNS_OP_NOTIFY(Zone change notification)
    // and DNS_OP_UPDATE(Zone update message), it is possible with answer
    if (!dns->qr && (dns->qd_count == 0 || dns->an_count != 0) &&
            dns->opcode != DNS_OP_NOTIFY &&
            dns->opcode != DNS_OP_UPDATE) {
        DEBUG_LOG(DBG_PARSER, p, "DNS invalide record count, q=%u a=%u.\n",
                  ntohs(dns->qd_count), ntohs(dns->an_count));
        return -1;
    }
    shift += sizeof(dns_hdr_t);

    uint16_t qd = ntohs(dns->qd_count);
    uint16_t an = ntohs(dns->an_count);

    //limit the question and answer max number in case of wrong dns type
    if ((qd + an) < MAX_RECORD_NUM) {
        questions = calloc(qd, sizeof(dns_question_t));
        answers = calloc(an, sizeof(dns_answer_t));
        if ((questions == NULL) ^ (answers == NULL)) {
            free(questions);
            free(answers);
            questions = NULL;
            answers = NULL;
        }
    }

    if (qd > 0) {
        DEBUG_LOG(DBG_PARSER, p, "DNS question record: %u\n", qd);
        shift = dns_question(p, ptr, len, shift, qd, questions, &qt_count);
        if (shift < 0) {
            if (questions != NULL){
                free(questions);
            }
            if (answers != NULL) {
                free(answers);
            }
            return -1;
        }
    }

    if (an > 0) {
        DEBUG_LOG(DBG_PARSER, p, "DNS answer record: %u\n", an);
        shift = dns_answer(p, ptr, len, shift, an, answers, &aw_count);
        if (shift < 0) {
            if (questions != NULL){
                free(questions);
            }
            if (answers != NULL) {
                free(answers);
            }
            return -1;
        }
    }

    if (qt_count > 0 && aw_count > 0) {
        get_domain_ip_mapping(p, questions, qd, answers, an);
    }
    if (questions != NULL){
        free(questions);
    }
    if (answers != NULL) {
        free(answers);
    }

    uint16_t ns = ntohs(dns->ns_count);
    if (ns > 0) {
        DEBUG_LOG(DBG_PARSER, p, "DNS authority record: %u\n", ns);
        shift = dns_answer(p, ptr, len, shift, ns, NULL, NULL);
        if (shift < 0) return -1;
    }

    uint16_t ar = ntohs(dns->ar_count);
    if (ar > 0) {
        DEBUG_LOG(DBG_PARSER, p, "DNS additional record: %u\n", ar);
        shift = dns_answer(p, ptr, len, shift, ar, NULL, NULL);
        if (shift < 0) return -1;
    }

    return shift;
}

// TCP
static void dns_tcp_parser(dpi_packet_t *p)
{
    dns_data_t *data;
    dns_wing_t *w;
    uint8_t *ptr;
    uint32_t len;

    if (p->sport != 53 && p->dport != 53) {
            dpi_fire_parser(p);
            return;
    }

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not DNS: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }

        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }

        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;

        dpi_put_parser_data(p, data);
    }

    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        int32_t sec_shift = u32_distance(dpi_pkt_seq(p), w->seq);
        ptr = dpi_pkt_ptr(p) + sec_shift;
        len = dpi_pkt_len(p) - sec_shift;
    } else {
        dpi_fire_parser(p);
        return;
    }

    while (true) {
        uint16_t msg_len;

        if (len < 2) return;
        msg_len = ntohs(*(uint16_t *)ptr);

#define DNS_TCP_MAX_MSG_LEN (4 * 1024)
#define DNS_OVERFLOW_THRES (2 * 1024)
#define DNS_OVERFLOW_THREAT_SIZE 1024

        // Parser is not fired in order to check against DNS overflow attack. To reduce false positives,
        // only work on port 53 traffic and only if DNS has been confirmed.
        if (unlikely((msg_len > DNS_OVERFLOW_THRES || len > DNS_OVERFLOW_THRES) &&
                     dpi_is_parser_final(p) && (p->session->server.port == 53))) {
            DEBUG_LOG(DBG_PARSER, p, "Oversized DNS packet: msg_len:%d len:%d\n", msg_len, len);
        } else if (msg_len > DNS_TCP_MAX_MSG_LEN || msg_len < sizeof(dns_hdr_t)) {
            dpi_fire_parser(p);
            return;
        }

        // Wait for full message.
        if (msg_len > len - 2) return;

        ptr += 2;
        len -= 2;

        int shift = dns_parser(p, ptr, len);

        if (unlikely((msg_len > DNS_OVERFLOW_THRES || len > DNS_OVERFLOW_THRES) &&
                     dpi_is_parser_final(p) && (p->session->server.port == 53))) {
            if (shift < 0 || msg_len - shift > DNS_OVERFLOW_THREAT_SIZE) {
                DEBUG_LOG(DBG_PARSER, p,
                          "DNS Overflow Attack: shift:%u msg_len:%u len:%u\n", shift, msg_len, len);
                dpi_threat_trigger(DPI_THRT_DNS_OVERFLOW, p,
                               "DNS Overflow Attack: message=%u parsed=%u", msg_len, shift);
            }
        } else if (shift < 0) {
            dpi_fire_parser(p);
            DEBUG_LOG(DBG_ERROR, p, "fake TCP DNS packet, sport=%d, dport=%d\n", p->sport, p->dport);
            return;
        }

        dpi_finalize_parser(p);

        // As pointer name is not fully parsed and length is not counted, shift
        // might not be same as msg_len.

        ptr += msg_len;
        len -= msg_len;

        w->seq = dpi_ptr_2_seq(p, ptr);
        dpi_set_asm_seq(p, w->seq);
    }
}

static void dns_tcp_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void dns_tcp_delete_data(void *data)
{
    free(data);
}

// UDP
static void dns_udp_parser(dpi_packet_t *p)
{
    uint8_t *ptr = dpi_pkt_ptr(p);
    uint32_t len = dpi_pkt_len(p);

    if (p->sport != 53 && p->dport != 53) {
            dpi_fire_parser(p);
            return;
    }

    int shift = dns_parser(p, ptr, len);

    // Parser is not fired in order to check against DNS overflow attack. To reduce false positives,
    // only work on port 53 traffic and only if DNS has been confirmed.
    if (unlikely(len > DNS_OVERFLOW_THRES && dpi_is_parser_final(p) && p->session->server.port == 53)) {
        if (shift < 0 || len - shift > DNS_OVERFLOW_THREAT_SIZE) {
            DEBUG_LOG(DBG_PARSER, p, "DNS Overflow Attack: shift:%u len:%u\n", shift, len);
            dpi_threat_trigger(DPI_THRT_DNS_OVERFLOW, p,
                           "DNS Overflow Attack: message=%u parsed=%u", len, shift);
        }
        return;
    }

    if (shift < 0) {
        dpi_fire_parser(p);
        DEBUG_LOG(DBG_ERROR, p, "fake UDP DNS packet, sport=%d, dport=%d\n", p->sport, p->dport);
        return;
    }

    dpi_finalize_parser(p);
}

static void dns_udp_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static dpi_parser_t dpi_parser_dns_tcp = {
    new_session: dns_tcp_new_session,
    delete_data: dns_tcp_delete_data,
    parser:      dns_tcp_parser,
    name:        "dns",
    ip_proto:    IPPROTO_TCP,
    type:        DPI_PARSER_DNS,
};

static dpi_parser_t dpi_parser_dns_udp = {
    new_session: dns_udp_new_session,
    delete_data: NULL,
    parser:      dns_udp_parser,
    name:        "dns",
    ip_proto:    IPPROTO_UDP,
    type:        DPI_PARSER_DNS,
};

dpi_parser_t *dpi_dns_tcp_parser(void)
{
    return &dpi_parser_dns_tcp;
}

dpi_parser_t *dpi_dns_udp_parser(void)
{
    return &dpi_parser_dns_udp;
}
