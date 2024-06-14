#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include "jansson.h"
#include "urcu.h"

#include "dpi/dpi_module.h"
#include "dpi/sig/dpi_search.h"

#define DUMP_POLICY_FILE "/var/log/dp.pol"
extern dpi_fqdn_hdl_t *g_fqdn_hdl;

static void dpi_ctrl_req_done(void)
{
    pthread_mutex_lock(&g_ctrl_req_lock);
    pthread_cond_signal(&g_ctrl_req_cond);
    pthread_mutex_unlock(&g_ctrl_req_lock);
}

static void dpi_dlp_ctrl_req_done(void)
{
    pthread_mutex_lock(&g_dlp_ctrl_req_lock);
    pthread_cond_signal(&g_dlp_ctrl_req_cond);
    pthread_mutex_unlock(&g_dlp_ctrl_req_lock);
}

void dpi_get_stats(io_stats_t *stats, dpi_stats_callback_fct cb)
{
    int i;

    DEBUG_LOG_FUNC_ENTRY(DBG_CTRL, NULL);

    for (i = 0; i < MAX_DP_THREADS; i ++) {
        cb(stats, &g_dpi_thread_data[i].stats);
    }
}

void dpi_get_device_counter(DPMsgDeviceCounter *c)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_CTRL, NULL);

    int i, j;
    for (i = 0; i < MAX_DP_THREADS; i ++) {
        c->ErrorPackets += g_dpi_thread_data[i].counter.err_pkts;
        c->NoWorkloadPackets += g_dpi_thread_data[i].counter.unkn_pkts;
        c->IPv4Packets += g_dpi_thread_data[i].counter.ipv4_pkts;
        c->IPv6Packets += g_dpi_thread_data[i].counter.ipv6_pkts;
        c->TCPPackets += g_dpi_thread_data[i].counter.tcp_pkts;
        c->TCPNoSessionPackets += g_dpi_thread_data[i].counter.tcp_nosess_pkts;
        c->UDPPackets += g_dpi_thread_data[i].counter.udp_pkts;
        c->ICMPPackets += g_dpi_thread_data[i].counter.icmp_pkts;
        c->OtherPackets += g_dpi_thread_data[i].counter.other_pkts;
        c->Assemblys += g_dpi_thread_data[i].counter.total_asms;
        c->FreedAssemblys += g_dpi_thread_data[i].counter.freed_asms;
        c->Fragments += g_dpi_thread_data[i].counter.total_frags;
        c->FreedFragments += g_dpi_thread_data[i].counter.freed_frags;
        c->TimeoutFragments += g_dpi_thread_data[i].counter.tmout_frags;
        c->TotalSessions += g_dpi_thread_data[i].counter.sess_id;
        c->TCPSessions += g_dpi_thread_data[i].counter.tcp_sess;
        c->UDPSessions += g_dpi_thread_data[i].counter.udp_sess;
        c->ICMPSessions += g_dpi_thread_data[i].counter.icmp_sess;
        c->IPSessions += g_dpi_thread_data[i].counter.ip_sess;
        c->DropMeters += g_dpi_thread_data[i].counter.drop_meters;
        c->ProxyMeters += g_dpi_thread_data[i].counter.proxy_meters;
        c->CurMeters += g_dpi_thread_data[i].counter.cur_meters;
        c->CurLogCaches += g_dpi_thread_data[i].counter.cur_log_caches;
        for (j = 0; j < DPI_PARSER_MAX; j ++) {
            c->ParserSessions[j] += g_dpi_thread_data[i].counter.parser_sess[j];
            c->ParserPackets[j] += g_dpi_thread_data[i].counter.parser_pkts[j];
        }
        c->PolicyType1Rules += g_dpi_thread_data[i].counter.type1_rules;
        c->PolicyType2Rules += g_dpi_thread_data[i].counter.type2_rules;
        c->PolicyDomains += g_dpi_thread_data[i].counter.domains;
        c->PolicyDomainIPs += g_dpi_thread_data[i].counter.domain_ips;
    }
}

void dpi_count_session(DPMsgSessionCount *c)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_CTRL, NULL);

    int i;
    for (i = 0; i < MAX_DP_THREADS; i ++) {
        c->CurSess += g_dpi_thread_data[i].counter.cur_sess;
        c->CurTCPSess += g_dpi_thread_data[i].counter.cur_tcp_sess;
        c->CurUDPSess += g_dpi_thread_data[i].counter.cur_udp_sess;
        c->CurICMPSess += g_dpi_thread_data[i].counter.cur_icmp_sess;
        c->CurIPSess += g_dpi_thread_data[i].counter.cur_ip_sess;
    }
}

// -- sessions

#define SESSIONS_PER_MSG ((DP_MSG_SIZE - sizeof(DPMsgHdr) - sizeof(DPMsgSessionHdr)) / sizeof(DPMsgSession))
#define SESSIONS_FIRST_ENTRY (DPMsgSession *)(th_dp_msg + sizeof(DPMsgHdr) + sizeof(DPMsgSessionHdr))

typedef struct session_args_ {
    uint16_t count;
} session_args_t;

static void send_sessions(int count)
{
    DEBUG_LOG(DBG_CTRL, NULL, "count=%u\n", count);

    DPMsgHdr *hdr = (DPMsgHdr *)th_dp_msg;
    DPMsgSessionHdr *dpsh = (DPMsgSessionHdr *)(th_dp_msg + sizeof(*hdr));
    uint16_t len = sizeof(*hdr) + sizeof(*dpsh) + sizeof(DPMsgSession) * count;

    hdr->Kind = DP_KIND_SESSION_LIST;
    hdr->Length = htons(len);
    hdr->More = 1;
    dpsh->Sessions = htons(count);
    g_io_callback->send_ctrl_binary(th_dp_msg, len);
}

static void netify_session_log(DPMsgSession *dps)
{
    dps->ID = htonl(dps->ID);
    dps->EtherType = htons(dps->EtherType);
    dps->ClientPort = htons(dps->ClientPort);
    dps->ServerPort = htons(dps->ServerPort);
    dps->ClientPkts = htonl(dps->ClientPkts);
    dps->ClientBytes = htonl(dps->ClientBytes);
    dps->ClientAsmPkts = htonl(dps->ClientAsmPkts);
    dps->ClientAsmBytes = htonl(dps->ClientAsmBytes);
    dps->ServerPkts = htonl(dps->ServerPkts);
    dps->ServerBytes = htonl(dps->ServerBytes);
    dps->ServerAsmPkts = htonl(dps->ServerAsmPkts);
    dps->ServerAsmBytes = htonl(dps->ServerAsmBytes);
    dps->Application = htons(dps->Application);
    dps->Age = htonl(dps->Age);
    dps->Idle = htons(dps->Idle);
    dps->Life = htons(dps->Life);
    dps->PolicyId = htonl(dps->PolicyId);
    dps->Flags = htons(dps->Flags);
    dps->ThreatID = htonl(dps->ThreatID);
    dps->XffApp = htons(dps->XffApp);
    dps->XffPort = htons(dps->XffPort);
    dps->EpSessCurIn = htonl(dps->EpSessCurIn);
    dps->EpSessIn12 = htonl(dps->EpSessIn12);
    dps->EpByteIn12 = htonll(dps->EpByteIn12);
}

static void dpi_list_session()
{
    int count;
    DPMsgSession *dps;

    DEBUG_LOG_FUNC_ENTRY(DBG_CTRL, NULL);

    count = 0;
    dps = SESSIONS_FIRST_ENTRY;

    struct cds_lfht_node *node;
    struct cds_lfht_iter iter;
    RCU_MAP_ITR_FOR_EACH(&th_session4_map, iter, node) {
        dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
        dpi_session_log(sess, dps);
        netify_session_log(dps);

        count ++;
        dps ++;
        if (count == SESSIONS_PER_MSG) {
            send_sessions(count);
            count = 0;
            dps = SESSIONS_FIRST_ENTRY;
        }
    }

    if (th_session4_proxymesh_map.map) {
        RCU_MAP_ITR_FOR_EACH(&th_session4_proxymesh_map, iter, node) {
            dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
            dpi_session_log(sess, dps);
            netify_session_log(dps);

            count ++;
            dps ++;
            if (count == SESSIONS_PER_MSG) {
                send_sessions(count);
                count = 0;
                dps = SESSIONS_FIRST_ENTRY;
            }
        }
    }

    RCU_MAP_ITR_FOR_EACH(&th_session6_map, iter, node) {
        dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
        dpi_session_log(sess, dps);

        count ++;
        dps ++;
        if (count == SESSIONS_PER_MSG) {
            send_sessions(count);
            count = 0;
            dps = SESSIONS_FIRST_ENTRY;
        }
    }

    if (th_session6_proxymesh_map.map) {
        RCU_MAP_ITR_FOR_EACH(&th_session6_proxymesh_map, iter, node) {
            dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
            dpi_session_log(sess, dps);
        
            count ++;
            dps ++;
            if (count == SESSIONS_PER_MSG) {
                send_sessions(count);
                count = 0;
                dps = SESSIONS_FIRST_ENTRY;
            }
        }
    }

    if (count > 0) {
        send_sessions(count);
    }
}

static void dpi_clear_session()
{
    struct cds_lfht_node *node;
    struct cds_lfht_iter iter;

    RCU_MAP_ITR_FOR_EACH(&th_session4_map, iter, node) {
        dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
        if (!g_sess_id_to_clear) {
            dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
        } else if (g_sess_id_to_clear == sess->id) {
            dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
            break;
        }
    }
    if (th_session4_proxymesh_map.map) {
        RCU_MAP_ITR_FOR_EACH(&th_session4_proxymesh_map, iter, node) {
            dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
            if (!g_sess_id_to_clear) {
                dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
            } else if (g_sess_id_to_clear == sess->id) {
                dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
                break;
            }
        }
    }
    RCU_MAP_ITR_FOR_EACH(&th_session6_map, iter, node) {
        dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
        if (!g_sess_id_to_clear) {
            dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
        } else if (g_sess_id_to_clear == sess->id) {
            dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
            break;
        }
    }
    if (th_session6_proxymesh_map.map) {
        RCU_MAP_ITR_FOR_EACH(&th_session6_proxymesh_map, iter, node) {
            dpi_session_t *sess = STRUCT_OF(node, dpi_session_t, node);
            if (!g_sess_id_to_clear) {
                dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
            } else if (g_sess_id_to_clear == sess->id) {
                dpi_session_delete(sess, DPI_SESS_TERM_NORMAL);
                break;
            }
        }
    }
}

static void dpi_session_delete_by_mac(struct ether_addr *mac_addr)
{
    struct cds_lfht_node *node;
    struct cds_lfht_iter iter;
    uint8_t *ep_mac;

    RCU_MAP_ITR_FOR_EACH(&th_session4_map, iter, node) {
        dpi_session_t *s = STRUCT_OF(node, dpi_session_t, node);
        ep_mac = (s->flags & DPI_SESS_FLAG_INGRESS)?s->server.mac:s->client.mac;
        if (!mac_cmp(ep_mac, (uint8_t *)mac_addr)) {
            continue;
        }
        dpi_session_delete(s, DPI_SESS_TERM_NORMAL);
    }

    if (th_session4_proxymesh_map.map) {
        RCU_MAP_ITR_FOR_EACH(&th_session4_proxymesh_map, iter, node) {
            dpi_session_t *s = STRUCT_OF(node, dpi_session_t, node);
            ep_mac = (s->flags & DPI_SESS_FLAG_INGRESS)?s->server.mac:s->client.mac;
            if (!mac_cmp(ep_mac, (uint8_t *)mac_addr)) {
                continue;
            }
            dpi_session_delete(s, DPI_SESS_TERM_NORMAL);
        }
    }

    RCU_MAP_ITR_FOR_EACH(&th_session6_map, iter, node) {
        dpi_session_t *s = STRUCT_OF(node, dpi_session_t, node);
        ep_mac = (s->flags & DPI_SESS_FLAG_INGRESS)?s->server.mac:s->client.mac;
        if (!mac_cmp(ep_mac, (uint8_t *)mac_addr)) {
            continue;
        }
        dpi_session_delete(s, DPI_SESS_TERM_NORMAL);
    }
    if (th_session6_proxymesh_map.map) {
        RCU_MAP_ITR_FOR_EACH(&th_session6_proxymesh_map, iter, node) {
            dpi_session_t *s = STRUCT_OF(node, dpi_session_t, node);
            ep_mac = (s->flags & DPI_SESS_FLAG_INGRESS)?s->server.mac:s->client.mac;
            if (!mac_cmp(ep_mac, (uint8_t *)mac_addr)) {
                continue;
            }
            dpi_session_delete(s, DPI_SESS_TERM_NORMAL);
        }
    }
}

bool iter_print_one_rule(struct cds_lfht_node *ht_node, void *args)
{
    FILE *logfp = (FILE *)args;
    dpi_rule_t *r = (dpi_rule_t *)ht_node;
    fprintf(logfp, "    REGULAR rule\n");
    fprintf(logfp, "        src:"DBG_IPV4_FORMAT" dst:"DBG_IPV4_FORMAT":dport %u proto:%u app:%u\n        "DP_POLICY_DESC_STR"\n\n", 
                DBG_IPV4_TUPLE(r->key.sip), DBG_IPV4_TUPLE(r->key.dip), r->key.dport, r->key.proto, r->key.app,
                DP_POLICY_DESC((&(r->desc))));
    return 0;
}

bool iter_print_one_range_rule(struct cds_lfht_node *ht_node, void *args)
{
    FILE *logfp = (FILE *)args;
    dpi_range_rule_t *r = (dpi_range_rule_t *)ht_node;
    dpi_range_rule_item_t  *p, *prev;
    fprintf(logfp, "    RANGE rule key ip:"DBG_IPV4_FORMAT" proto:%u ingress:%x\n",
                DBG_IPV4_TUPLE(r->key.ip), r->key.proto, r->key.flag);
    p = r->range_rule_list;
    if (p) {
        fprintf(logfp, "    RANGE rule list\n");
    }
    while (p) {
        prev = p;
        p = p->next;
        fprintf(logfp, "        low:src:"DBG_IPV4_FORMAT" dst:"DBG_IPV4_FORMAT":dport %u proto:%u app:%u\n"
            "        high:src:"DBG_IPV4_FORMAT" dst:"DBG_IPV4_FORMAT":dport %u proto:%u app:%u\n        "
            DP_POLICY_DESC_STR"\n\n", 
            DBG_IPV4_TUPLE(prev->key_l.sip), DBG_IPV4_TUPLE(prev->key_l.dip), prev->key_l.dport, prev->key_l.proto, prev->key_l.app,
            DBG_IPV4_TUPLE(prev->key_h.sip), DBG_IPV4_TUPLE(prev->key_h.dip), prev->key_h.dport, prev->key_h.proto, prev->key_h.app,
            DP_POLICY_DESC((&(prev->desc))));
    }
    return 0;
}

static void dpi_dump_policy()
{
    FILE *logfp = NULL;

    if (logfp == NULL) {
        logfp = fopen(DUMP_POLICY_FILE, "w");
        if (logfp != NULL) {
            int flags;

            if ((flags = fcntl(fileno(logfp), F_GETFL, 0)) == -1) {
                flags = 0;
            }
            fcntl(fileno(logfp), F_SETFL, flags | O_NONBLOCK);
        }
    }
    struct cds_lfht_node *node;
    dpi_detector_t *dlp_detector = NULL;

    // Iterate through all MAC
    RCU_MAP_FOR_EACH(&g_ep_map, node) {
        io_mac_t *mac = STRUCT_OF(node, io_mac_t, node);
        if (mac == NULL) continue;
        io_ep_t *ep = mac->ep;
        if (ep == NULL) continue;
        if (ep->dlp_detector != NULL)
        {
            dlp_detector = (dpi_detector_t *)ep->dlp_detector;
        }
        dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)ep->policy_hdl;

        fprintf(logfp, "mac="DBG_MAC_FORMAT, DBG_MAC_TUPLE(mac->mac));
        if (hdl) {
            fprintf(logfp, " hdl_ver:%u default_action:%d fqdn:%d\n", hdl->ver, hdl->def_action, DPI_POLICY_HAS_FQDN(hdl));
            rcu_map_for_each(&hdl->policy_map, iter_print_one_rule, logfp);
            rcu_map_for_each(&hdl->range_policy_map, iter_print_one_range_rule, logfp);
        } else {
            fprintf(logfp, "\n");
        }
        fflush(logfp);
    }

    if (g_fqdn_hdl != NULL) {
        struct cds_lfht_node *name_node;
        // Iterate through fqdn map
        RCU_MAP_FOR_EACH(&g_fqdn_hdl->fqdn_name_map, name_node) {
            fqdn_name_entry_t *name_entry = STRUCT_OF(name_node, fqdn_name_entry_t, node);
            fprintf(logfp, "FQDN name:%s code:%x\n", name_entry->r->name, ntohl(name_entry->r->code));

            // Iterate through all ips
            fqdn_ipv4_item_t *ipv4_itr, *ipv4_next;
            //for wildcard fqdn, it is possible that name<->iplist mapping is not established
            //at the time of info print, so we need to initialize iplist to avoid crash
            if(name_entry->r->iplist.prev==NULL && name_entry->r->iplist.next==NULL) {
                CDS_INIT_LIST_HEAD(&(name_entry->r->iplist));
            }
            cds_list_for_each_entry_safe(ipv4_itr, ipv4_next, &(name_entry->r->iplist), node) {
                fprintf(logfp, "    FQDN match ip:"DBG_IPV4_FORMAT"\n", DBG_IPV4_TUPLE(ipv4_itr->ip));
            }
            fflush(logfp);
        }
    }

    if (th_ip_fqdn_storage_map.map != NULL) {
        struct cds_lfht_node *ip_fqdn_storage_node;
        // Iterate through ip fqdn storage map
        RCU_MAP_FOR_EACH(&th_ip_fqdn_storage_map, ip_fqdn_storage_node) {
            dpi_ip_fqdn_storage_entry_t *entry = STRUCT_OF(ip_fqdn_storage_node, dpi_ip_fqdn_storage_entry_t, node);
            fprintf(logfp, "IP-FQDN storage map, IP:"DBG_IPV4_FORMAT" FQDN name:%s\n", DBG_IPV4_TUPLE(entry->r->ip), entry->r->name);

            fflush(logfp);
        }
    }

    if (dlp_detector != NULL)
    {
        dpi_print_siglist_fp(dlp_detector, logfp);
        fflush(logfp);
    }
    dpi_print_ip4_internal_fp(logfp);
    fflush(logfp);
}

// --

#define METERS_PER_MSG ((DP_MSG_SIZE - sizeof(DPMsgHdr) - sizeof(DPMsgMeterHdr)) / sizeof(DPMsgMeter))

typedef struct meter_args_ {
    uint16_t count;
} meter_args_t;

static void send_meters(meter_args_t *args)
{
    DEBUG_LOG(DBG_CTRL, NULL, "count=%u\n", args->count);

    DPMsgHdr *hdr = (DPMsgHdr *)th_dp_msg;
    DPMsgMeterHdr *dpmh = (DPMsgMeterHdr *)(th_dp_msg + sizeof(*hdr));
    uint16_t len = sizeof(*hdr) + sizeof(*dpmh) + sizeof(DPMsgMeter) * args->count;

    hdr->Kind = DP_KIND_METER_LIST;
    hdr->Length = htons(len);
    hdr->More = 1;
    dpmh->Meters = htons(args->count);
    g_io_callback->send_ctrl_binary(th_dp_msg, len);
}

static bool list_one_meter(struct cds_lfht_node *ht_node, void *args)
{
    meter_args_t *margs = args;

    DPMsgMeter *dpm;
    dpi_meter_t *m = STRUCT_OF(ht_node, dpi_meter_t, node);

    meter_info_t *info = dpi_get_meter_info(m->type);
    if (info == NULL) return false;

    dpm = (DPMsgMeter *)(th_dp_msg + sizeof(DPMsgHdr) + sizeof(DPMsgMeterHdr) +
                         sizeof(DPMsgMeter) * margs->count);
    mac_cpy(dpm->EPMAC, m->ep_mac);
    dpm->MeterID = info->id;
    dpm->Count = htonl(m->count);
    dpm->LastCount = htonl(m->last_count);
    dpm->Span = info->span;
    dpm->UpperLimit = htonl(info->upper_limit);
    dpm->LowerLimit = htonl(info->lower_limit);
    dpm->Idle = htons(timer_wheel_entry_get_idle(&m->ts_entry, th_snap.tick));
    dpm->Flags = 0;
    if (likely(m->log.EtherType == ntohs(ETH_P_IP))) {
        dpm->Flags |= DPMETER_FLAG_IPV4;
        ip4_cpy(dpm->PeerIP, (uint8_t *)&m->peer_ip.ip4);
    } else {
        memcpy(dpm->PeerIP, &m->peer_ip.ip6, 16);
    }
    if (FLAGS_TEST(m->log.Flags, DPLOG_FLAG_TAP)) {
        dpm->Flags |= DPMETER_FLAG_TAP;
    }

    margs->count ++;
    if (unlikely(margs->count == METERS_PER_MSG)) {
        send_meters(margs);
        margs->count = 0;
    }

    return false;
}

static void dpi_list_meter()
{
    DEBUG_LOG_FUNC_ENTRY(DBG_CTRL, NULL);

    meter_args_t args;
    args.count = 0;
    rcu_map_for_each(&th_meter_map, list_one_meter, &args);

    if (args.count > 0) {
        send_meters(&args);
    }
}

void dpi_handle_ctrl_req(int req, io_ctx_t *ctx)
{
    DEBUG_LOG(DBG_CTRL, NULL, "req=%d\n", req);

    th_snap.tick = ctx->tick;

    switch (req) {
    case CTRL_REQ_LIST_SESSION:
        dpi_list_session();
        break;
    case CTRL_REQ_CLEAR_SESSION:
        dpi_clear_session();
        break;
    case CTRL_REQ_LIST_METER:
        dpi_list_meter();
        break;
    case CTRL_REQ_DEL_MAC:
        if (g_mac_addr_to_del) {
            dpi_session_delete_by_mac(g_mac_addr_to_del);
        }
        break;
    case CTRL_REQ_DUMP_POLICY:
        dpi_dump_policy();
        break;
    }

    dpi_ctrl_req_done();
    DEBUG_LOG(DBG_CTRL, NULL, "done\n");
    return;
}

void dpi_handle_dlp_ctrl_req(int req)
{
    DEBUG_LOG(DBG_CTRL, NULL, "dlp received req=%d\n", req);
    struct timespec before_time , after_time;
    float time_taken; 
    clock_gettime(CLOCK_MONOTONIC, &before_time);

    switch (req) {
    case CTRL_DLP_REQ_BLD:
        if (g_build_detector) {
            dpi_build_dlp_tree(g_build_detector);
            clock_gettime(CLOCK_MONOTONIC, &after_time);
            time_taken = (float)(after_time.tv_sec - before_time.tv_sec) * 1e9; 
            time_taken = (float)((time_taken + (after_time.tv_nsec - before_time.tv_nsec)) * 1e-9); 
            DEBUG_DLP("Building dlp time %.9fs\n", time_taken);
        }
        break;
    case CTRL_DLP_REQ_DEL:
        if (g_release_detector) {
            dpi_dlp_release_detector(g_release_detector);
            free(g_release_detector);
            clock_gettime(CLOCK_MONOTONIC, &after_time);
            time_taken = (float)(after_time.tv_sec - before_time.tv_sec) * 1e9; 
            time_taken = (float)((time_taken + (after_time.tv_nsec - before_time.tv_nsec)) * 1e-9); 
            DEBUG_DLP("Release dlp time %.9fs\n", time_taken);
        }
        break;
    }

    dpi_dlp_ctrl_req_done();
    DEBUG_LOG(DBG_CTRL, NULL, "done\n");
    return;
}
