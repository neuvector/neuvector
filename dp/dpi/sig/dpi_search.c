#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "dpi/sig/dpi_search.h"

extern dpi_sig_search_api_t *dpi_dlp_hs_search_register (void);
extern bool cmp_mac_prefix(void *m1, void *prefix);

static void dpi_build_dlp_search_tree (dpi_sig_search_t *search, dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (search->search_api== NULL) {
        search->context = dpi_dlp_hs_search_register()->create();
        if (search->context == NULL) {
            return;
        }
        dpi_hs_search_t *hs_search = (dpi_hs_search_t *)(search->context);
        hs_search->detector = (dpi_detector_t *)sig->detector;
        search->search_api= dpi_dlp_hs_search_register();
    }

    search->search_api->add_sig(search->context, sig);

    search->count ++;
}

static void
dpi_build_dlp_service_tree (dpi_sig_service_tree_t *service, dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    service->count ++;

    dpi_build_dlp_search_tree(&service->client_server, sig);
}

static void
dpi_build_dlp_protocol_tree (dpi_sig_protocol_tree_t *proto, dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    proto->count ++;

    dpi_build_dlp_service_tree(&proto->service_unknown, sig);
}

static void dpi_build_dlp_detect_tree (dpi_sig_detect_tree_t *tree, dpi_sig_t *sig)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    tree->count ++;

    dpi_build_dlp_protocol_tree(&tree->protocol_unknown, sig);
}

static void dpi_compile_search_tree (dpi_sig_search_t *search)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (search->count == 0) {
        return;
    }

    if (search->search_api->compile != NULL) {
        search->search_api->compile(search->context);
    }
}

static void dpi_compile_service_tree (dpi_sig_service_tree_t *service)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (service->count == 0) {
        return;
    }

    dpi_compile_search_tree(&service->client_server);
}

static void dpi_compile_protocol_tree (dpi_sig_protocol_tree_t *proto)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (proto->count == 0) {
        return;
    }

    dpi_compile_service_tree(&proto->service_unknown);
}


static void dpi_build_hs_mpse_tree (dpi_detector_t *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sig_macro_sig_t *macro, *macro_next;
    dpi_sig_t *sig, *sig_next;
    dpi_sig_detect_tree_t *detect_tree;

    detect_tree = calloc(1, sizeof(dpi_sig_detect_tree_t));
    if (detect_tree != NULL) {
        memset(&detector->dlp_hs_summary, 0, sizeof(dpi_hs_summary_t));
        cds_list_for_each_entry_safe(macro, macro_next, &detector->dlpSigList, node) {
            cds_list_for_each_entry_safe(sig, sig_next, &(macro->sigs), node) {
                dpi_build_dlp_detect_tree(detect_tree, sig);
            }
        }

        dpi_compile_protocol_tree(&detect_tree->protocol_unknown);

        detector->tree = detect_tree;
        DEBUG_DLP("Multi pattern subtotal: hyperscan db_count(%u) allocated, db_bytes(%u), scratch_size(%u)!\n",
            detector->dlp_hs_summary.db_count, detector->dlp_hs_summary.db_bytes, detector->dlp_hs_summary.scratch_size);
    
        detector->dlp_hs_summary.db_count += detector->dlp_pcre_hs_summary.db_count;
        detector->dlp_hs_summary.db_bytes += detector->dlp_pcre_hs_summary.db_bytes;
        detector->dlp_hs_summary.scratch_size += detector->dlp_pcre_hs_summary.scratch_size;

        DEBUG_DLP("Overall total: hyperscan db_count(%u) allocated, db_bytes(%u), scratch_size(%u)!\n",
            detector->dlp_hs_summary.db_count, detector->dlp_hs_summary.db_bytes, detector->dlp_hs_summary.scratch_size);
    }
}

static void dpi_dlp_release_search_tree (dpi_sig_search_t *search)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (search->count == 0) {
        return;
    }

    search->search_api->release(search->context);

    search->context = search->search_api = NULL;
    search->count = 0;
}

static void dpi_dlp_release_service_tree (dpi_sig_service_tree_t *service)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (service->count == 0) {
        return;
    }

    dpi_dlp_release_search_tree(&service->client_server);

    service->count = 0;
}

static void dpi_dlp_release_protocol_tree (dpi_sig_protocol_tree_t *proto)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (proto->count == 0) {
        return;
    }

    dpi_dlp_release_service_tree(&proto->service_unknown);

    proto->count = 0;
}


static void dpi_dlp_release_detector_tree (dpi_sig_detect_tree_t *tree)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_dlp_release_protocol_tree(&tree->protocol_unknown);

    free(tree);
}

void dpi_print_siglist(dpi_detector_t *detector) 
{
    dpi_sig_macro_sig_t *macro, *macro_next;
    dpi_sig_t *sig, *sig_next;
    cds_list_for_each_entry_safe(macro, macro_next, &detector->dlpSigList, node) {
        cds_list_for_each_entry_safe(sig, sig_next, &(macro->sigs), node) {
            DEBUG_CTRL("sig: name(%s),"
                        " text: (%s), "
                        "id: (%d) "
                        "flags: (0x%x)"
                        "severity: (%d)"
                        "action: (%d)\n",
                        macro->conf.name,
                        macro->conf.text,
                        macro->conf.id,
                        macro->conf.flags,
                        macro->conf.severity,
                        macro->conf.action);
        }
    }
}

void dpi_print_siglist_fp(dpi_detector_t *detector, FILE *logfp)
{
    dpi_sig_macro_sig_t *macro, *macro_next;
    dpi_sig_t *sig, *sig_next;
    cds_list_for_each_entry_safe(macro, macro_next, &detector->dlpSigList, node) {
        cds_list_for_each_entry_safe(sig, sig_next, &(macro->sigs), node) {
            fprintf(logfp, "sig: name(%s),"
                        " text: (%s), "
                        "id: (%d) "
                        "flags: (0x%x)"
                        "severity: (%d)"
                        "action: (%d)\n",
                        macro->conf.name,
                        macro->conf.text,
                        macro->conf.id,
                        macro->conf.flags,
                        macro->conf.severity,
                        macro->conf.action);
        }
    }
}

void dpi_dlp_release_dlprulelist (dpi_detector_t *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sig_macro_sig_t *macro, *macro_next;
    
    cds_list_for_each_entry_safe(macro, macro_next, &detector->dlpSigList, node) {
        cds_list_del((struct cds_list_head *)macro);
        dpi_dlp_release_macro_rule(macro);
    }
}

void dpi_hs_free_global_context(dpi_detector_t *detector) 
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    hs_free_scratch(detector->dlp_hs_mpse_build_scratch);
    detector->dlp_hs_mpse_build_scratch = NULL;
    hs_free_scratch(detector->dlp_hs_mpse_scan_scratch);
    detector->dlp_hs_mpse_scan_scratch = NULL;
    
    hs_free_scratch(detector->dlp_hs_pcre_build_scratch);
    detector->dlp_hs_pcre_build_scratch = NULL;
    hs_free_scratch(detector->dlp_hs_pcre_scan_scratch);
    detector->dlp_hs_pcre_scan_scratch = NULL;
}

void dpi_dlp_release_detector (dpi_detector_t *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT, NULL);
    DEBUG_DLP("release detector(%p)\n", detector);

    if (!detector) return;

    if (detector->tree != NULL) {
        dpi_dlp_release_detector_tree(detector->tree);
        detector->tree = NULL;
    }
    //dpi_print_siglist(detector);
    dpi_dlp_release_dlprulelist(detector);
    dpi_hs_free_global_context(detector);
}


void dpi_dlp_init_hs_search (void *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT, NULL);
    dpi_dlp_hs_search_register()->init(detector);
}

void dpi_build_dlp_tree (dpi_detector_t *dlp_detector)
{
    if (dlp_detector->tree == NULL) {
        DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
        dpi_build_hs_mpse_tree(dlp_detector);
        if (dlp_detector->tree == NULL) {
            return;
        }
    }
}

static bool
dpi_dlp_match_type_dlpopt (dpi_packet_t *p, dpi_sig_t *s, dpi_sig_context_type_t t)
{
    dpi_sigopt_node_t *node_itr, *node_next;
    p->dlp_pat_context = t;
    p->dlp_match_seq = 0;
    p->dlp_match_type = DPI_SIG_CONTEXT_TYPE_MAX;

    cds_list_for_each_entry_safe(node_itr, node_next, &s->uri_opts, node) {
        if(!node_itr->sigapi->handler(node_itr, p, s)) {
            return false;
        }
    }

    return true;
}

static bool dpi_dlp_match_non_type_dlpopt (struct cds_list_head *sigopt, dpi_packet_t *p, dpi_sig_t *s)
{
    dpi_sigopt_node_t *node_itr, *node_next;

    p->dlp_pat_context = DPI_SIG_CONTEXT_TYPE_MAX;
    cds_list_for_each_entry_safe(node_itr, node_next, sigopt, node) {
        if(!node_itr->sigapi->handler(node_itr, p, s)) {
            return false;
        }
    }

    return true;
}

static void dpi_match_sig (dpi_packet_t *p, dpi_sig_user_t *user)
{
    dpi_sig_t *sig = user->sig;

    dpi_match_t *m = &p->dlp_match_results[p->dlp_results];

    p->dlp_match_flags = 0;

    if (!dpi_dlp_match_type_dlpopt(p, sig, DPI_SIG_CONTEXT_TYPE_URI_ORIGIN)) {
        return;
    }
    if (!dpi_dlp_match_non_type_dlpopt(&sig->header_opts, p, sig)) {
        return;
    }
    if (!dpi_dlp_match_non_type_dlpopt(&sig->body_opts, p, sig)) {
        return;
    }
    if (!dpi_dlp_match_non_type_dlpopt(&sig->packet_opts, p, sig)) {
        return;
    }

    DEBUG_LOG(DBG_DETECT, p, "pattern matched sig conf id(%u),sig id(%u): %s\n",
              sig->conf->id, sig->sig_id, sig->conf->name);

    if (p->dlp_results < DPI_MAX_MATCH_RESULT) {
        m->user = user;
        m->dlp_match_seq = p->dlp_match_seq;
        m->dlp_match_flags = p->dlp_match_flags;

        p->dlp_results ++;
    }

    DEBUG_LOG(DBG_DETECT, p, "num of results(%d) matched dlp rule %u: %s\n",
              p->dlp_results, sig->conf->id, sig->conf->name);
}

static void dpi_sig_match_sigs (dpi_packet_t *p)
{
    int i;
    dpi_sig_user_t *user;

    for (i = 0; i < p->dlp_candidates; i ++) {
        user = p->dlp_match_candidates[i].user;
        dpi_match_sig(p, user);
    }
}

dpi_sig_user_t* dpi_find_sig_user(struct cds_list_head *sig_user_list, dpi_sig_t *sig, io_dlp_cfg_t *dlp_cfg)
{
    dpi_sig_user_link_t *sig_user_itr, *sig_user_next;

    cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, sig_user_list, node) {
        if (sig_user_itr->sig_user) {
            dpi_sig_t *tsig = sig_user_itr->sig_user->sig;
            if (tsig && tsig==sig) {
                sig_user_itr->sig_user->sig = sig;
                sig_user_itr->sig_user->action = dlp_cfg->action;
                return sig_user_itr->sig_user;
            }
        }
    }

    dpi_sig_user_t *new_user = (dpi_sig_user_t *)calloc(1, sizeof(dpi_sig_user_t));
    if (!new_user) {
        DEBUG_DLP("OOM while creating new sig user\n");
        return NULL;
    }
    new_user->sig = sig;
    new_user->flags = sig->conf->flags;
    new_user->action = dlp_cfg->action;
    new_user->severity = sig->conf->severity;

    dpi_sig_user_link_t *new_sig_user_link = (dpi_sig_user_link_t *)calloc(1, sizeof(dpi_sig_user_link_t));
    if (!new_sig_user_link) {
        DEBUG_DLP("OOM while creating new sig user link\n");
        free(new_user);
        return NULL;
    }
    new_sig_user_link->sig_user = new_user;

    if (sig_user_list->prev == NULL || sig_user_list->next == NULL) {
        CDS_INIT_LIST_HEAD(sig_user_list);
    }
    cds_list_add_tail((struct cds_list_head *)new_sig_user_link, sig_user_list);

    return new_user;
}

dpi_sig_user_t *dpi_dlp_ep_match (dpi_packet_t *p, dpi_sig_t *sig){
    dpi_sig_user_t *user = NULL;
    if (!p || !sig) return user;

    io_ep_t *ep = p->ep;
    io_dlp_cfg_t key;

    key.sigid = sig->conf->id;
    key.action = sig->conf->action;
    if (key.sigid >= DPI_SIG_MIN_WAF_SIG_ID) {
        if (!FLAGS_TEST(p->flags, DPI_PKT_FLAG_DETECT_WAF)) {
            return user;
        }
        //DEBUG_DLP("match waf rid:(%d)!\n", key.sigid);
        io_dlp_cfg_t *waf_cfg = rcu_map_lookup(&ep->waf_cfg_map, &key);
        if (waf_cfg != NULL) {
            if (waf_cfg->sig_user_list.prev == NULL && waf_cfg->sig_user_list.next == NULL) {
                CDS_INIT_LIST_HEAD(&waf_cfg->sig_user_list);
            }
            user = dpi_find_sig_user(&waf_cfg->sig_user_list, sig, waf_cfg);
        } 
    } else {
        if (!FLAGS_TEST(p->flags, DPI_PKT_FLAG_DETECT_DLP)) {
            return user;
        }
        //DEBUG_DLP("match dlp rid:(%d)!\n", key.sigid);
        io_dlp_cfg_t *dlp_cfg = rcu_map_lookup(&ep->dlp_cfg_map, &key);
        if (dlp_cfg != NULL) {
            if (dlp_cfg->sig_user_list.prev == NULL && dlp_cfg->sig_user_list.next == NULL) {
                CDS_INIT_LIST_HEAD(&dlp_cfg->sig_user_list);
            }
            user = dpi_find_sig_user(&dlp_cfg->sig_user_list, sig, dlp_cfg);
        } 
    }
    return user;
}

void dpi_dlp_add_candidate (dpi_packet_t *p, dpi_sig_t *sig, bool nc)
{

    dpi_sig_user_t *user = NULL;
    if ((user=dpi_dlp_ep_match(p, sig)) == NULL) {
        return;
    }
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (p->dlp_candidates < DPI_MAX_MATCH_CANDIDATE) {
        p->dlp_match_candidates[p->dlp_candidates].user = user;
        p->dlp_match_candidates[p->dlp_candidates].nc = nc;
        p->dlp_candidates ++;
    } else {
        DEBUG_LOG(DBG_DETECT, NULL, "candidate buffer overflow\n");

        p->dlp_candidates_overflow = 1;

        dpi_sig_match_sigs(p);

        p->dlp_match_candidates[0].user = user;
        p->dlp_match_candidates[0].nc = nc;
        p->dlp_candidates = 1;
    }

    p->has_dlp_candidates = 1;
}

typedef struct dpi_dlp_context_status_ {
    uint8_t url    :1,
            header :1,
            body   : 1;
} dpi_dlp_context_status_t;

static dpi_dlp_context_status_t base_app_dlp_context_status[] = {
[DPI_APP_HTTP - DPI_APP_BASE_START] = {1, 1, 1,},
[DPI_APP_SSL - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_SSH - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_DNS - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_DHCP - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_NTP - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_TFTP - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_ECHO - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_RTSP - DPI_APP_BASE_START] = {0, 0, 0,},
[DPI_APP_SIP - DPI_APP_BASE_START] = {0, 0, 0,},
};

static dpi_dlp_context_status_t app_dlp_context_status[] = {
[DPI_APP_MYSQL - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_REDIS - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_ZOOKEEPER - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_CASSANDRA - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_MONGODB - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_POSTGRESQL - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_KAFKA - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_COUCHBASE - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_WORDPRESS - DPI_APP_PROTO_MARK] = {1, 1, 1,},
[DPI_APP_ACTIVEMQ - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_COUCHDB - DPI_APP_PROTO_MARK] = {1, 1, 1,},
[DPI_APP_ELASTICSEARCH - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_MEMCACHED - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_RABBITMQ - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_RADIUS - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_VOLTDB - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_CONSUL - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_SYSLOG - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_ETCD - DPI_APP_PROTO_MARK] = {1, 1, 1,},
[DPI_APP_SPARK - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_APACHE - DPI_APP_PROTO_MARK] = {1, 1, 1,},
[DPI_APP_NGINX - DPI_APP_PROTO_MARK] = {1, 1, 1,},
[DPI_APP_JETTY - DPI_APP_PROTO_MARK] = {1, 1, 1,},
[DPI_APP_NODEJS - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_ERLANG_EPMD - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_TNS - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_TDS - DPI_APP_PROTO_MARK] = {0, 0, 0,},
[DPI_APP_GRPC - DPI_APP_PROTO_MARK] = {0, 0, 0,},
};

static bool dpi_support_dlp_context (dpi_packet_t *p, dpi_sig_context_class_t c)
{
    uint32_t app = 0;
    dpi_session_t *s = p->session;

    if (s == NULL) {
        app = DP_POLICY_APP_UNKNOWN;
    } else {
        app = s->app?s->app:(s->base_app?s->base_app:DP_POLICY_APP_UNKNOWN);
    }
    if (app == DP_POLICY_APP_UNKNOWN) {
        return false;
    }
    if (dpi_is_base_app(app)) {
        if (c == DPI_SIG_CONTEXT_CLASS_HEADER) {
            return base_app_dlp_context_status[app - DPI_APP_BASE_START].header > 0;
        } else if (c == DPI_SIG_CONTEXT_CLASS_BODY) {
            return base_app_dlp_context_status[app - DPI_APP_BASE_START].body > 0;
        } else if (c == DPI_SIG_CONTEXT_CLASS_URI) {
            return base_app_dlp_context_status[app - DPI_APP_BASE_START].url > 0;
        }
    } else {
        if (c == DPI_SIG_CONTEXT_CLASS_HEADER) {
            return app_dlp_context_status[app - DPI_APP_PROTO_MARK].header > 0;
        } else if (c == DPI_SIG_CONTEXT_CLASS_BODY) {
            return app_dlp_context_status[app - DPI_APP_PROTO_MARK].body > 0;
        } else if (c == DPI_SIG_CONTEXT_CLASS_URI) {
            return app_dlp_context_status[app - DPI_APP_PROTO_MARK].url > 0;
        }
    }
    return false;
}

static void dpi_arrange_search_buffer (dpi_packet_t *p)
{
    dpi_sig_context_type_t t;

    for (t = 0; t < DPI_SIG_CONTEXT_TYPE_MAX; t ++) {
        dpi_sig_context_class_t c = dpi_dlp_ctxt_type_2_cat(t);
        dpi_dlp_area_t *dlparea = &p->dlp_area[t];
        uint32_t pkt_seq = dpi_pkt_seq(p);
        uint32_t pkt_end_seq = dpi_pkt_end_seq(p);

        //check if service protocol support url,header,body
        //context or not, if not dlp area set to packet payload
        if ((c == DPI_SIG_CONTEXT_CLASS_HEADER ||
            c == DPI_SIG_CONTEXT_CLASS_BODY ||
            c == DPI_SIG_CONTEXT_CLASS_URI) && !dpi_support_dlp_context(p, c)) {
            dlparea->dlp_ptr = dpi_pkt_ptr(p);
            dlparea->dlp_len = dpi_pkt_len(p);
            dlparea->dlp_start = pkt_seq;
            dlparea->dlp_end = pkt_end_seq;
            dlparea->dlp_offset = 0;
        }
    
        switch (c) {
        case DPI_SIG_CONTEXT_CLASS_HEADER:
        case DPI_SIG_CONTEXT_CLASS_BODY:
            if (dlparea->dlp_ptr != NULL) {
                // dlp_area have been assigned
                break;
            }

            if (u32_gt(dlparea->dlp_start, pkt_end_seq - 1) ||
                u32_lt(dlparea->dlp_end, pkt_seq) ||
                u32_gt(dlparea->dlp_start, dlparea->dlp_end - 1)) {
                break;
            }

            if (u32_lt(dlparea->dlp_start, pkt_seq)) {
                dlparea->dlp_ptr = dpi_pkt_ptr(p);
                dlparea->dlp_offset = pkt_seq - dlparea->dlp_start;
            } else {
                // ignore this pkt for dlp detection
                if (dpi_pkt_ptr(p) + dlparea->dlp_start - pkt_seq > dpi_pkt_end(p)) {
                    dlparea->dlp_ptr = dpi_pkt_end(p);
                    dlparea->dlp_offset = 0;
                    dlparea->dlp_len = 0;
                    break;
                }

                dlparea->dlp_ptr = dpi_pkt_ptr(p) + dlparea->dlp_start - pkt_seq;
                dlparea->dlp_offset = 0;
            }
            if (u32_gt(dlparea->dlp_end, pkt_end_seq)) {
                dlparea->dlp_len = dpi_pkt_end(p) - dlparea->dlp_ptr;
            } else {
                dlparea->dlp_len = dlparea->dlp_end - dlparea->dlp_start - dlparea->dlp_offset;
            }
            break;
        case DPI_SIG_CONTEXT_CLASS_URI:
            // other ranges have been set by their parsers
            dlparea->dlp_offset = 0;
            break;
        case DPI_SIG_CONTEXT_CLASS_PACKET:
            if (dlparea->dlp_ptr != NULL && dlparea->dlp_len == 0) {
                // set ptr and len in parser to ingore
                //this packet for dlp detection to avoid
                //false positive
                break;
            }
            dlparea->dlp_ptr = dpi_pkt_ptr(p);
            dlparea->dlp_len = dpi_pkt_len(p);
            dlparea->dlp_start = pkt_seq;
            dlparea->dlp_end = pkt_end_seq;
            dlparea->dlp_offset = 0;
            
            break;
        default:
            break;
        }
    }
}

static inline bool dpi_is_known_app (dpi_session_t *sess)
{
    if (BITMASK_RANGE_TEST(sess->parser_bits, 0, DPI_PARSER_MAX)) {
        return true;
    } else {
        return false;
    }
}

static void dpi_dlp_detect_search_tree (dpi_packet_t *p, dpi_sig_search_t *search)
{
    if (search->count == 0) {
        return;
    }

    search->search_api->detect(search->context, p);
}

static bool
dpi_dlp_detect_service_tree (dpi_packet_t *p, dpi_sig_service_tree_t *service)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    if (service->count == 0) {
        return false;
    }

    dpi_dlp_detect_search_tree(p, &service->client_server);

    return true;
}

static bool
dpi_dlp_detect_protocol_tree (dpi_packet_t *p, dpi_sig_protocol_tree_t *proto)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    bool continue_detect = false;

    if (proto->count == 0) {
        return false;
    }

    continue_detect = dpi_dlp_detect_service_tree(p, &proto->service_unknown);

    return continue_detect;
}

static bool dpi_dlp_search_detector_tree (dpi_packet_t *p, dpi_sig_detect_tree_t *tree)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    return dpi_dlp_detect_protocol_tree(p, &tree->protocol_unknown);
}

void dpi_set_pkt_decision(dpi_packet_t *p, int action)
{
    DEBUG_LOG(DBG_DETECT, p, "packet action(%s) category(%d), dlp action(%s) category(%d)\n", 
    debug_action_name(p->action), dpi_dlp_get_action_category(p->action), 
    debug_action_name(action), dpi_dlp_get_action_category(action));

    if (dpi_dlp_get_action_category(p->action) >
                                            dpi_dlp_get_action_category(action)) {
        return;
    }

    if (p->session != NULL) {
        p->session->action = action;
    }
    
    p->action = action;
    if (action != DPI_ACTION_ALLOW) {
        FLAGS_SET(p->flags, DPI_PKT_FLAG_SKIP_PARSER);
        FLAGS_SET(p->flags, DPI_PKT_FLAG_SKIP_PATTERN);
    }
}

static void dpi_sift_matchs (dpi_packet_t *p)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);

    int i;
    dpi_sig_user_t *best_user;
    dpi_sig_t *best_sig;
    dpi_match_t *m;
    uint8_t action = DPI_ACTION_ALLOW;

    //report all the matches
    for (i = 0; i < p->dlp_results; i ++) {
        m = &p->dlp_match_results[i];
        best_user = p->dlp_match_results[i].user;
        if (best_user->action == DPI_ACTION_ALLOW) {
            best_user->severity = THRT_SEVERITY_MEDIUM;
        } else if (best_user->action == DPI_ACTION_DROP) {
            best_user->severity = THRT_SEVERITY_CRITICAL;
        }

        best_sig = best_user->sig;
        if (best_user->action > action) {
            action = best_user->action;
        }

        if (isproxymesh) {
            if (best_sig->conf->id >= DPI_SIG_MIN_WAF_SIG_ID) {
                dpi_dlp_log_by_sig(p, m, "WAF: id %u, service mesh", best_sig->conf->id);
            } else {
                dpi_dlp_log_by_sig(p, m, "DLP: id %u, service mesh", best_sig->conf->id);
            }
        } else {
            if (best_sig->conf->id >= DPI_SIG_MIN_WAF_SIG_ID) {
                dpi_dlp_log_by_sig(p, m, "WAF: id %u", best_sig->conf->id);
            } else {
                dpi_dlp_log_by_sig(p, m, "DLP: id %u", best_sig->conf->id);
            }
        }
    }
    dpi_set_pkt_decision(p, action);
}

//per packet decision whether to detect or not
bool dpi_waf_ep_policy_check (dpi_packet_t *p) {
    if (!p || !p->ep || !(p->ep->dlp_detector)) {
            return false;
    }
    // no session yet,  continue detect
    if (!p->session) {
        return true;
    }

    io_ep_t *ep = p->ep;
    dpi_detector_t *dlp_detector = (dpi_detector_t *)ep->dlp_detector;
    dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)ep->policy_hdl;
    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);
    io_dlp_ruleid_t key;
    dpi_session_t *sess = p->session;
    key.rid = sess->policy_desc.id;
    uint32_t app = 0;

    app = sess->app?sess->app:(sess->base_app?sess->base_app:DP_POLICY_APP_UNKNOWN);
    if (app == DPI_APP_SSL || app == DPI_APP_SSH) {
        //DEBUG_DLP("No waf inspection for SSL/SSH protocol, app(%u)!\n", app);
        return false;
    }

    //if network policy is disabled, go through detection.
    if (th_disable_net_policy) {
        return true;
    }

    if (!ep->waf_inside) {
        io_dlp_ruleid_t *waf_rid = rcu_map_lookup(&ep->waf_rid_map, &key);
        //only detect traffic that match network policy id for outside wl
        //and always detect traffic between sidecar and service
        if (waf_rid != NULL || isproxymesh) {
            //DEBUG_DLP("OUTSIDE find rid:(%d) in waf_rid_map continue!\n", waf_rid->rid);
            return true;
        }
        return false;
    } else {
        //for internal east-west traffic with no policy, no waf detect
        //always go through waf detection for proxymesh traffic
        //such as istio/linkerd
        if (!isproxymesh && sess->policy_desc.id == 0 &&
            sess->policy_desc.action == DP_POLICY_ACTION_OPEN &&
            (sess->policy_desc.flags & POLICY_DESC_INTERNAL) ) {
            if (hdl && hdl->def_action == DP_POLICY_ACTION_DENY) {
                return true;
            }
            if (dlp_detector->dlp_apply_dir & DP_POLICY_APPLY_EGRESS) {
                if ((sess->policy_desc.flags & POLICY_DESC_TUNNEL) ||
                    (sess->policy_desc.flags & POLICY_DESC_HOSTIP)) {
                    //DEBUG_DLP("traffic from tunnel and host needs to be checked!\n");
                    return true;
                } else {
                    //DEBUG_DLP("POLICY_APPLY_EGRESS internal east-west open action, policyid 0 traffic no dlp check!\n");
                    return false;
                }
            } else {
                //DEBUG_DLP("POLICY_APPLY_INGRESS internal east-west open action, policyid 0 traffic no dlp check!\n");
                return false;
            }
        }
        return true;
    }
}

//per packet decision whether to detect or not
bool dpi_dlp_ep_policy_check (dpi_packet_t *p) {
    if (!p || !p->ep || !(p->ep->dlp_detector)) {
            return false;
    }
    // no session yet,  continue detect
    if (!p->session) {
        return true;
    }

    io_ep_t *ep = p->ep;
    dpi_detector_t *dlp_detector = (dpi_detector_t *)ep->dlp_detector;
    dpi_policy_hdl_t *hdl = (dpi_policy_hdl_t *)ep->policy_hdl;
    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);
    io_dlp_ruleid_t key;
    dpi_session_t *sess = p->session;
    key.rid = sess->policy_desc.id;
    uint32_t app = 0;

    app = sess->app?sess->app:(sess->base_app?sess->base_app:DP_POLICY_APP_UNKNOWN);
    if (app == DPI_APP_SSL || app == DPI_APP_SSH) {
        //DEBUG_DLP("No dlp inspection for SSL/SSH protocol, app(%u)!\n", app);
        return false;
    }

    //if network policy is disabled, go through detection.
    if (th_disable_net_policy) {
        return true;
    }

    if (!ep->dlp_inside) {
        io_dlp_ruleid_t *dlp_rid = rcu_map_lookup(&ep->dlp_rid_map, &key);
        //only detect traffic that match network policy id for outside wl
        //and always detect traffic between sidecar and service
        if (dlp_rid != NULL || isproxymesh) {
            //DEBUG_DLP("OUTSIDE find rid:(%d) in dlp_rid_map continue!\n", dlp_rid->rid);
            return true;
        } 
        return false;
    } else {
        //for internal east-west traffic with no policy, no dlp detect
        if (!isproxymesh && sess->policy_desc.id == 0 && 
            sess->policy_desc.action == DP_POLICY_ACTION_OPEN &&
            (sess->policy_desc.flags & POLICY_DESC_INTERNAL) ) {
            if (hdl && hdl->def_action == DP_POLICY_ACTION_DENY) {
                return true;
            }
            if (dlp_detector->dlp_apply_dir & DP_POLICY_APPLY_EGRESS) {
                if ((sess->policy_desc.flags & POLICY_DESC_TUNNEL) || 
                    (sess->policy_desc.flags & POLICY_DESC_HOSTIP)) {
                    //DEBUG_DLP("traffic from tunnel needs to be checked!\n");
                    return true;
                } else {
                    //DEBUG_DLP("POLICY_APPLY_EGRESS internal east-west open action, policyid 0 traffic no dlp check!\n");
                    return false;
                }
            } else {
                //DEBUG_DLP("POLICY_APPLY_INGRESS internal east-west open action, policyid 0 traffic no dlp check!\n");
                return false;
            }
        }

        io_dlp_ruleid_t *dlp_rid = rcu_map_lookup(&ep->dlp_rid_map, &key);
        //not to continue because traffic is within dlp group
        //traffic between sidecar and service is considered within dlp group.
        if (dlp_rid != NULL || isproxymesh) {
            //DEBUG_DLP("INSIDE find rid:(%d) in dlp_rid_map not continue!\n", dlp_rid->rid);
            return false;
        } 
        return true;
    }
}

bool dpi_process_detector(dpi_packet_t *p)
{
    if (!p || !p->ep || !p->ep->dlp_detector) return true;

    io_ep_t *ep = p->ep;
    dpi_detector_t *detector = (dpi_detector_t *)ep->dlp_detector;
    dpi_sig_detect_tree_t *tree;
    bool continue_detect;

    tree = detector->tree;
    if (tree == NULL) {
        return true;
    }

    dpi_arrange_search_buffer(p);

    // reset match candidates.
    p->dlp_results = 0;
    p->dlp_candidates = 0;
    p->dlp_candidates_overflow = 0;
    p->has_dlp_candidates = 0;

    continue_detect = dpi_dlp_search_detector_tree(p, tree);

    if (!p->has_dlp_candidates) {
        return continue_detect;
    }
    // full-match
    dpi_sig_match_sigs(p);

    if (p->dlp_results > 0) {
        dpi_sift_matchs(p);
    }

    return true;
}

