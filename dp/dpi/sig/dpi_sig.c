#include "dpi/sig/dpi_sig.h"
#include "dpi/sig/dpi_search.h"
#include "dpi/dpi_module.h"

uint32_t DlpRuleCount = 0;

#define MAX_USER_SIG_COUNT (DPI_SIG_MAX_USER_SIG_ID - DPI_SIG_MIN_USER_SIG_ID + 1)
#define MAX_USER_SIG_LEN 2048

static dpi_sigopt_status_t
dpi_dlp_parse_opts_routine (dpi_dlp_parser_t *parser, char **opts, int count,
                            dpi_sig_t *rule, void *dlpdetector);

static dpi_dlp_parser_t DlpRuleParser = {
    parse_dlpopts:    dpi_dlp_parse_opts_routine,
};

static dpi_sigopt_status_t
dpi_dlp_parse_ruleopt (const char *sigopt, const char *value, struct cds_list_head *sigopt_list,
                  dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sigopt_status_t ret = DPI_SIGOPT_OK;
    dpi_sigopt_reg_t *opt_itr, *opt_next;

    cds_list_for_each_entry_safe(opt_itr, opt_next, sigopt_list, sonode) {
        if (strcasecmp(opt_itr->soname, sigopt) == 0) {
            ret = opt_itr->soapi.parser((char *)value, sig);
            BITMASK_SET(sig->opt_inuse, opt_itr->soapi.type);
            return ret;
        }
    }

    return DPI_SIGOPT_UNKNOWN_OPTION;
}

static dpi_sigopt_status_t
dpi_dlp_parse_opts_routine (dpi_dlp_parser_t *parser, char **opts, int count,
                            dpi_sig_t *sig, void *dlpdetector)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    char *option, *value;
    dpi_sig_config_t *conf;
    dpi_sigopt_status_t ret = DPI_SIGOPT_OK;
    int i;

    for (i = 0; i < count; i ++) {
        
        value = strchr(opts[i], ' ');
        if (value) {
            *value = '\0';
            value ++;
        }
        
        option = opts[i];
        strip_str(option);
        strip_str(value);

        // remove "" from value, do NOT do str_strip afterwards
        strip_str_quote(value);

        ret = dpi_dlp_parse_ruleopt(option, value, &parser->dlprulelist, sig);

        if (ret != DPI_SIGOPT_OK) {
            DEBUG_ERROR(DBG_ERROR, "Dlp rule(%s):(%d) has invalid option(%s : %s)\n",sig->conf->name, sig->conf->id, option, value);
            return ret;
        }
    }

    conf = sig->conf;

    if (DlpRuleCount == MAX_USER_SIG_COUNT) {
        DEBUG_ERROR(DBG_ERROR, "too many dlp rule (%d) created, max allowed is (%d) ", DlpRuleCount, MAX_USER_SIG_COUNT);
        return DPI_SIGOPT_TOO_MANY_DLP_RULE;
    }
    //conf->text null terminated
    if (strlen(conf->text) >= MAX_USER_SIG_LEN) {
        DEBUG_ERROR(DBG_ERROR, "dlp rule len(%d) too long, max allowed is (%d) ", strlen(conf->text), MAX_USER_SIG_LEN);
        return DPI_SIGOPT_VALUE_TOO_LONG;
    }

    if((conf->id < DPI_SIG_MIN_USER_SIG_ID ||
        conf->id > DPI_SIG_MAX_USER_SIG_ID) &&
        (conf->id < DPI_SIG_MIN_PRE_USER_SIG_ID ||
        conf->id > DPI_SIG_MAX_PRE_USER_SIG_ID) &&
        (conf->id < DPI_SIG_MIN_WAF_SIG_ID ||
        conf->id > DPI_SIG_MAX_WAF_SIG_ID)){

        DEBUG_ERROR(DBG_ERROR,
        "rule id should be between (%d) and (%d) "
        "or predefined rule id between (%d) and (%d) "
        "or predefined rule id between (%d) and (%d)\n",
        DPI_SIG_MIN_USER_SIG_ID, DPI_SIG_MAX_USER_SIG_ID,
        DPI_SIG_MIN_PRE_USER_SIG_ID, DPI_SIG_MAX_PRE_USER_SIG_ID,
        DPI_SIG_MIN_WAF_SIG_ID, DPI_SIG_MAX_WAF_SIG_ID);

        return DPI_SIGOPT_INVALID_USER_SIG_ID;
    }

    DlpRuleCount ++;
    //DEBUG_LOG(DBG_DETECT, NULL, "Dlp rule count(%d)\n", DlpRuleCount);

    dpi_dlp_post_parse_rule(sig);

    return DPI_SIGOPT_OK;
}

static void dpi_dlp_release_ruleopts (struct cds_list_head *options)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sigopt_node_t *node_itr, *node_next;

    cds_list_for_each_entry_safe(node_itr, node_next, options, node) {
        cds_list_del((struct cds_list_head *)node_itr);
        if (node_itr->sigapi && node_itr->sigapi->release) {
            node_itr->sigapi->release(node_itr);
        } else {
            free(node_itr);
        }
    }
}

void dpi_dlp_release_macro_rule (dpi_sig_macro_sig_t *macro)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sig_t *sig_itr, *sig_next;

    if (macro == NULL) {
        return;
    }

    if (macro->conf.text) {
       free(macro->conf.text);
    }

    if (macro->conf.name) {
        free(macro->conf.name);
    }
    
    if (macro->conf.description) {
       free(macro->conf.description);
    }
    cds_list_for_each_entry_safe(sig_itr, sig_next, &macro->sigs, node) {
        cds_list_del((struct cds_list_head *)sig_itr);

        dpi_dlp_release_ruleopts(&sig_itr->uri_opts);
        dpi_dlp_release_ruleopts(&sig_itr->header_opts);
        dpi_dlp_release_ruleopts(&sig_itr->body_opts);
        dpi_dlp_release_ruleopts(&sig_itr->packet_opts);

        free(sig_itr);
        
    }

    free(macro);
}

static void dpi_dlp_init_macro_rulelist(dpi_sig_macro_sig_t *macro)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    if(!macro) return;
    
    if(macro->sigs.prev==NULL && macro->sigs.next==NULL) {
        CDS_INIT_LIST_HEAD(&macro->sigs);
    }
}

static void dpi_dlp_init_rule_optlist(dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    if (sig->packet_opts.next == NULL && sig->packet_opts.prev == NULL) {
        CDS_INIT_LIST_HEAD(&sig->packet_opts);
    }
    if (sig->uri_opts.next == NULL && sig->uri_opts.prev == NULL) {
        CDS_INIT_LIST_HEAD(&sig->uri_opts);
    }
    if (sig->header_opts.next == NULL && sig->header_opts.prev == NULL) {
        CDS_INIT_LIST_HEAD(&sig->header_opts);
    }
    if (sig->body_opts.next == NULL && sig->body_opts.prev == NULL) {
        CDS_INIT_LIST_HEAD(&sig->body_opts);
    }
}

static dpi_sigopt_status_t
dpi_dlp_parse_rule (dpi_dlp_parser_t *parser, char **opts, int count,
                    const char *text, dpi_detector_t *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sigopt_status_t ret = DPI_SIGOPT_OK;
    dpi_sig_macro_sig_t *macro;
    dpi_sig_t *sig;
    int i;
    //text is null terminated
    int text_len = strlen(text);

    for (i = 0; i < count; i ++) {
        strip_str(opts[i]);
    }

    // allocate storage for macro rule
    macro = calloc(1, sizeof(dpi_sig_macro_sig_t));
    if (macro == NULL) {
        return DPI_SIGOPT_FAILED;
    }

    macro->conf.text = (char *) calloc(text_len+1, sizeof(char));
    if (macro->conf.text == NULL) {
        dpi_dlp_release_macro_rule(macro);
        return DPI_SIGOPT_FAILED;
    }

    memcpy(macro->conf.text, text, text_len);
    macro->conf.text[text_len]='\0';

    dpi_dlp_init_macro_rulelist(macro);

    sig = calloc(1, sizeof(dpi_sig_t));
    if (sig == NULL) {
        dpi_dlp_release_macro_rule(macro);
        return DPI_SIGOPT_FAILED;
    }
    sig->conf = &macro->conf;
    sig->macro = macro;
    sig->detector = (void *)detector;
    dpi_dlp_init_rule_optlist(sig);

    cds_list_add((struct cds_list_head *)sig, &macro->sigs);

    ret = parser->parse_dlpopts(parser, opts, count, sig, (void *)detector);

    if (ret != DPI_SIGOPT_OK) {
        dpi_dlp_release_macro_rule(macro);
        return ret;
    }
    dpi_sig_macro_sig_t *exist;

    if ((exist = sig->macro) != macro) {
        cds_list_del((struct cds_list_head *)sig);

        exist->conf.action = max(exist->conf.action, macro->conf.action);
        exist->conf.severity = max(exist->conf.severity, macro->conf.severity);

        sig->conf = &exist->conf;
        cds_list_add_tail((struct cds_list_head *)sig, &exist->sigs);
        dpi_dlp_release_macro_rule(macro);
    } else {
        cds_list_add_tail((struct cds_list_head *)macro, &detector->dlpSigList);
    }

    return DPI_SIGOPT_OK;
}

static void dpi_dlp_hs_combine_pcres (dpi_sig_t *sig, struct cds_list_head *opts)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sigopt_pcre_pattern_t *pcre_itr, *pcre_next;
    int i = 0;
    cds_list_for_each_entry_safe(pcre_itr, pcre_next, opts, node.node) {
        for (i = 0; i < DPI_MAX_PCRE_PATTERNS; i ++) {
            if (pcre_itr->pcre.hs_db != NULL && 
                !(pcre_itr->pcre.hs_flags & HS_FLAG_PREFILTER) &&
                !(FLAGS_TEST(pcre_itr->flags, DPI_SIGOPT_PAT_FLAG_NEGATIVE))
                && sig->hs_pats[i] == NULL) {
                sig->hs_pats[i] = &pcre_itr->node;
                if (sig->hs_count < DPI_MAX_PCRE_PATTERNS) {
                    sig->hs_count ++;
                }
                break;
            } 
        }
    }
}

void dpi_dlp_post_parse_rule (dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sig_config_t *conf = sig->conf;

    conf->severity = THRT_SEVERITY_CRITICAL;
    conf->action = DPI_ACTION_ALLOW;

    dpi_dlp_hs_combine_pcres(sig, &sig->uri_opts);
    dpi_dlp_hs_combine_pcres(sig, &sig->header_opts);
    dpi_dlp_hs_combine_pcres(sig, &sig->body_opts);
    dpi_dlp_hs_combine_pcres(sig, &sig->packet_opts);

    DEBUG_LOG(DBG_DETECT, NULL, "%s\n", conf->text);

    if (!cds_list_empty(&sig->uri_opts)) {
        BITMASK_SET(sig->pat_inuse, DPI_SIG_CONTEXT_CLASS_URI);
    }
    if (!cds_list_empty(&sig->header_opts)) {
        BITMASK_SET(sig->pat_inuse, DPI_SIG_CONTEXT_CLASS_HEADER);
    }
    if (!cds_list_empty(&sig->body_opts)) {
        BITMASK_SET(sig->pat_inuse, DPI_SIG_CONTEXT_CLASS_BODY);
    }
    if (!cds_list_empty(&sig->packet_opts)) {
        BITMASK_SET(sig->pat_inuse, DPI_SIG_CONTEXT_CLASS_PACKET);
    }
}

dpi_action_cate_t dpi_dlp_get_action_category(int act)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    
    switch (act) {
        case DPI_ACTION_NONE:
            return DPI_CAT_NONE;
        case DPI_ACTION_ALLOW:         
            return DPI_CAT_DETECTION;
        case DPI_ACTION_BYPASS:
            return DPI_CAT_BYPASS;
        default:
            return DPI_CAT_PREVENTION;
    }
}

static dpi_sig_context_class_t ContextType2Class[DPI_SIG_CONTEXT_TYPE_MAX] = {
    [DPI_SIG_CONTEXT_TYPE_URI_ORIGIN]         DPI_SIG_CONTEXT_CLASS_URI,
    [DPI_SIG_CONTEXT_TYPE_HEADER]             DPI_SIG_CONTEXT_CLASS_HEADER,
    [DPI_SIG_CONTEXT_TYPE_BODY]               DPI_SIG_CONTEXT_CLASS_BODY,
    [DPI_SIG_CONTEXT_TYPE_SQL_QUERY]          DPI_SIG_CONTEXT_CLASS_BODY,
    [DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN]      DPI_SIG_CONTEXT_CLASS_PACKET,
};

dpi_sig_context_class_t dpi_dlp_ctxt_type_2_cat (dpi_sig_context_type_t t)
{
    return ContextType2Class[t];
}

static void dpi_register_dlp_ruleopt_api (struct cds_list_head *list, const char *name,
                                      dpi_sigopt_api_t *sigapi)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);

    dpi_sigopt_reg_t *sonode;

    sonode = (dpi_sigopt_reg_t *)calloc(1, sizeof(dpi_sigopt_reg_t));
    if (sonode) {
        sonode->soname = name;
        memcpy(&sonode->soapi, sigapi, sizeof(dpi_sigopt_api_t));
        cds_list_add_tail((struct cds_list_head *)sonode, list);
    }
}

void dpi_dlp_register_options (dpi_dlp_parser_t *dlpruleparser)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT,NULL);

    if (dlpruleparser->dlprulelist.next == NULL &&
        dlpruleparser->dlprulelist.prev == NULL) {
        CDS_INIT_LIST_HEAD(&dlpruleparser->dlprulelist);
    }
    dpi_register_dlp_ruleopt_api(&dlpruleparser->dlprulelist,
                             "sig_id", dpi_sigopt_sig_id_register());
    dpi_register_dlp_ruleopt_api(&dlpruleparser->dlprulelist,
                             "name", dpi_sigopt_name_register());
    dpi_register_dlp_ruleopt_api(&dlpruleparser->dlprulelist,
                             "context", dpi_sigopt_context_register());
    dpi_register_dlp_ruleopt_api(&dlpruleparser->dlprulelist,
                             "pcre", dpi_sigopt_pcre_register());
}

void dpi_dlp_init(void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT,NULL);
    dpi_dlp_register_options(&DlpRuleParser);
}

void dpi_dlp_proc(char *dlp_sig_opts, void *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT,NULL);

    if (dlp_sig_opts != NULL) {
        char *sig;
        char **opts;
        int opt_count;
        
        sig = strdup(dlp_sig_opts);
        if (sig == NULL) {
            DEBUG_LOG(DBG_INIT|DBG_DETECT,NULL,"cannot allocate memory for signature\n");
            return;
        }
        strip_str(sig);
        opts = str_split(sig, ";", &opt_count);

        if (opt_count > 0) {
            dpi_dlp_parse_rule(&DlpRuleParser, opts,opt_count,
                                dlp_sig_opts, (dpi_detector_t *)detector);
        }
        free_split(opts, opt_count);
        free(sig);
    }
}

static dpi_detector_t *dpi_dlp_detector_init(int apply_dir)
{
    dpi_detector_t *detector;
    detector = calloc(sizeof(dpi_detector_t), 1);
    if (!detector) {
        DEBUG_ERROR(DBG_DETECT, "Out of memory!");
        return NULL;

    }
    detector->dlp_apply_dir = apply_dir;
    //per detector dlpSigList
    CDS_INIT_LIST_HEAD(&detector->dlpSigList);

    //per detector mpse/pcre build and scan scratch space
    detector->dlp_hs_mpse_build_scratch = NULL;
    detector->dlp_hs_mpse_scan_scratch = NULL;
    detector->dlp_hs_pcre_build_scratch = NULL;
    detector->dlp_hs_pcre_scan_scratch = NULL;

    dpi_dlp_init_hs_search((void *)detector);

    return detector;
}

dpi_detector_t *g_release_detector = NULL;
static int dp_dlp_free_detector(dpi_detector_t *detector)
{
    g_release_detector = detector;
    DEBUG_DLP("g_release_detector(%p) dlp_ref_cnt(%d)\n", g_release_detector, g_release_detector->dlp_ref_cnt);

    dp_dlp_wait_ctrl_req_thr(CTRL_DLP_REQ_DEL);

    g_release_detector = NULL;
    return 0;
}

dpi_detector_t *g_build_detector = NULL;
static int dp_dlp_build_detector(dpi_detector_t *detector)
{
    g_build_detector = detector;
    DEBUG_DLP("g_build_detector(%p) dlp_ref_cnt(%d)\n", g_build_detector, g_build_detector->dlp_ref_cnt);

    dp_dlp_wait_ctrl_req_thr(CTRL_DLP_REQ_BLD);

    g_build_detector = NULL;
    return 0;
}

void dpi_dlp_detector_destroy(dpi_detector_t *detector)
{
    if (detector->dlp_ref_cnt > 1) {
        detector->dlp_ref_cnt--;
        return;
    }
    /*
     *send request to bld_dlp thread to free dlp
     *detection tree
     */
    dp_dlp_free_detector(detector);
}

void dp_dlp_destroy(void *dlp_detector)
{
    if (dlp_detector) {
        dpi_dlp_detector_destroy((dpi_detector_t *)dlp_detector);
    }
}
static uint16_t dlp_detector_ver = 0;
#define GET_NEW_DLP_DETECTOR_VER()  ((++dlp_detector_ver)?dlp_detector_ver:(++dlp_detector_ver))

static int dpi_dlp_detect_update(struct ether_addr *mac_addr, dpi_detector_t *new_dlp_detector)
{
    void *buf;
    io_ep_t *ep;
    dpi_detector_t *old_dlp_detector;

    if (!mac_addr) {
        return -1;
    }
    rcu_read_lock();
    buf = rcu_map_lookup(&g_ep_map, mac_addr);
    if (!buf) {
        rcu_read_unlock();
        DEBUG_DLP("Dlp update detector cannot find mac: "DBG_MAC_FORMAT "\n", DBG_MAC_TUPLE(*mac_addr));
        return -1;
    }
    ep = GET_EP_FROM_MAC_MAP(buf);

    old_dlp_detector = (dpi_detector_t *)ep->dlp_detector;

    if (new_dlp_detector) {
        ep->dlp_detector = (void *)new_dlp_detector;
        new_dlp_detector->dlp_ref_cnt++;
    }
    ep->dlp_detect_ver = new_dlp_detector ? new_dlp_detector->dlp_ver : 0;
    rcu_read_unlock();

    if (old_dlp_detector) {
        if (old_dlp_detector->dlp_ref_cnt < 2) {
            synchronize_rcu();
        }
        dpi_dlp_detector_destroy(old_dlp_detector);
    }

    if (new_dlp_detector) {
        DEBUG_DLP("mac: "DBG_MAC_FORMAT" dlp detector %p ver %u dlp_ref_cnt (%u) done\n",
                DBG_MAC_TUPLE(*mac_addr), new_dlp_detector, ep->dlp_detect_ver, new_dlp_detector->dlp_ref_cnt);
    }
    return 0;
}

static int dpi_dlp_detect_add_mac(struct ether_addr *add_mac_addr, dpi_detector_t *exist_dlp_detector)
{
    void *buf;
    io_ep_t *ep;
    dpi_detector_t *old_dlp_detector;

    if (!add_mac_addr) {
        return -1;
    }
    rcu_read_lock();
    buf = rcu_map_lookup(&g_ep_map, add_mac_addr);
    if (!buf) {
        rcu_read_unlock();
        DEBUG_DLP("Dlp add mac detector cannot find mac: "DBG_MAC_FORMAT "\n", DBG_MAC_TUPLE(*add_mac_addr));
        return -1;
    }
    ep = GET_EP_FROM_MAC_MAP(buf);
    old_dlp_detector = (dpi_detector_t *)ep->dlp_detector;
    if (exist_dlp_detector){
        exist_dlp_detector->dlp_ref_cnt++;
    }
    ep->dlp_detector = (void *)exist_dlp_detector;
    ep->dlp_detect_ver = exist_dlp_detector ? exist_dlp_detector->dlp_ver : 0;
    rcu_read_unlock();

    if (old_dlp_detector) {
        if (old_dlp_detector->dlp_ref_cnt < 2) {
            synchronize_rcu();
        }
        dpi_dlp_detector_destroy(old_dlp_detector);
    }

    if (exist_dlp_detector){
        DEBUG_DLP("addmac: "DBG_MAC_FORMAT" dlp add mac detector %p ver %u, dlp_ref_cnt(%u) done\n",
                DBG_MAC_TUPLE(*add_mac_addr), exist_dlp_detector, ep->dlp_detect_ver, exist_dlp_detector->dlp_ref_cnt);
    }
    return 0;
}

static dpi_detector_t *dpi_dlp_get_detector (struct ether_addr *old_mac_addr)
{
    void *buf;
    io_ep_t *ep;
    dpi_detector_t *old_dlp_detector;

    if (!old_mac_addr) {
        return NULL;
    }
    rcu_read_lock();
    buf = rcu_map_lookup(&g_ep_map, old_mac_addr);
    if (!buf) {
        rcu_read_unlock();
        DEBUG_DLP("Dlp get detector cannot find mac: "DBG_MAC_FORMAT "\n", DBG_MAC_TUPLE(*old_mac_addr));
        return NULL;
    }
    ep = GET_EP_FROM_MAC_MAP(buf);

    old_dlp_detector = (dpi_detector_t *)ep->dlp_detector;
    rcu_read_unlock();

    DEBUG_DLP("oldmac: "DBG_MAC_FORMAT" get dlp detector %p ver %u done\n",
               DBG_MAC_TUPLE(*old_mac_addr), old_dlp_detector, ep->dlp_detect_ver);
    return old_dlp_detector;
}

static int dpi_dlp_detect_release(struct ether_addr *del_mac_addr)
{
    void *buf;
    io_ep_t *ep;
    dpi_detector_t *old_dlp_detector;

    if (!del_mac_addr) {
        return -1;
    }
    rcu_read_lock();
    buf = rcu_map_lookup(&g_ep_map, del_mac_addr);
    if (!buf) {
        rcu_read_unlock();
        DEBUG_DLP("Dlp release detector cannot find mac: "DBG_MAC_FORMAT "\n", DBG_MAC_TUPLE(*del_mac_addr));
        return -1;
    }
    ep = GET_EP_FROM_MAC_MAP(buf);

    old_dlp_detector = (dpi_detector_t *)ep->dlp_detector;
    ep->dlp_detector = NULL;
    ep->dlp_detect_ver = 0;
    rcu_read_unlock();

    if (old_dlp_detector) {
        if (old_dlp_detector->dlp_ref_cnt < 2) {
            synchronize_rcu();
        }
        dpi_dlp_detector_destroy(old_dlp_detector);
    }
    DEBUG_DLP("del mac: "DBG_MAC_FORMAT" release dlp detector %p ver %u done\n",
               DBG_MAC_TUPLE(*del_mac_addr), old_dlp_detector, ep->dlp_detect_ver);
    return 0;
}

int dpi_sig_bld(dpi_dlpbld_t *dlpsig, int flag)
{
    int i,j,k;
    char dlpsig_buf[MAX_USER_SIG_LEN];
    int len = 0;
    int len1 =0;
    static dpi_detector_t *dlpDetector = NULL;
    DEBUG_DLP("# of macs: (%d), # of delete macs: (%d), # of dlp rules: (%d) flag 0x%x\n",
               dlpsig->num_macs, dlpsig->num_del_macs, dlpsig->num_dlp_rules, flag);

    if (flag & MSG_START) {
       if (dlpDetector) {
           DEBUG_ERROR(DBG_DETECT, "old DLP DETECTOR %p exists!\n", dlpDetector);
           dpi_dlp_detector_destroy(dlpDetector);
           dlpDetector = NULL;
       }
    } else {
        if (!dlpDetector) {
            DEBUG_ERROR(DBG_DETECT, "missed dlp msg start!\n");
            return -1;
        }
    }

    if (flag & MSG_START) {
        dlpDetector = dpi_dlp_detector_init(dlpsig->apply_dir);
        if (!dlpDetector) {
            return -1;
        }
        dlpDetector->dlp_ver = GET_NEW_DLP_DETECTOR_VER();
        memset(&dlpDetector->dlp_pcre_hs_summary, 0, sizeof(dpi_hs_summary_t));
    }
    //build SigList for updated dlp rules
    for (j = 0; j < dlpsig->num_dlp_rules; j ++) {
        len = sprintf(dlpsig_buf, 
            "name %s;"
            "sig_id %u;",
            dlpsig->dlp_rule_list[j].rulename,
            dlpsig->dlp_rule_list[j].sigid
            );
        for (k = 0; k < dlpsig->dlp_rule_list[j].num_dlp_rule_pats; k ++) {
            len1 = sprintf(&dlpsig_buf[len], "pcre %s;",
                dlpsig->dlp_rule_list[j].dlp_rule_pat_list[k].rule_pattern);
                len += len1;
        }
        dlpsig_buf[len]='\0';
        //parse each dlp rule and store into SigList
        dpi_dlp_proc(dlpsig_buf, (void *)dlpDetector);
    }
    
    if (flag & MSG_END) {
        DEBUG_DLP("PARSE DLP RULE DONE!\n");
        DEBUG_DLP("Single pattern subtotal: hyperscan db_count(%u) allocated, db_bytes(%u), scratch_size(%u)!\n",
            dlpDetector->dlp_pcre_hs_summary.db_count, dlpDetector->dlp_pcre_hs_summary.db_bytes, dlpDetector->dlp_pcre_hs_summary.scratch_size);
        //dpi_print_siglist(dlpDetector);
    }

    if (!(flag & MSG_END)) {
        return 0;
    }
    if (dlpsig->num_dlp_rules == 0) {
        //there is no new dlp rules to build detect tree
        //thus release all old detector
        for (i = 0; i < dlpsig->num_macs; i++) {
            dpi_dlp_detect_release(&dlpsig->mac_list[i]);
        }
    } else {
        //after we parse all the dlp rules into SigList
        //we need to build detect tree
        for (i = 0; i < dlpsig->num_macs; i++) {
            dpi_dlp_detect_update(&dlpsig->mac_list[i], dlpDetector);
        }
    }
    //some of the ep no longer need dlp service
    for (i = 0; i < dlpsig->num_del_macs; i++) {
        dpi_dlp_detect_release(&dlpsig->del_mac_list[i]);
    }
    if (dlpDetector) {
        DEBUG_DLP("dlpDetector(%p) dlp_ref_cnt(%d) \n", dlpDetector, dlpDetector->dlp_ref_cnt);
    }
    if (dlpDetector && dlpDetector->dlp_ref_cnt == 0) {
        dpi_dlp_detector_destroy(dlpDetector);
    } else if (dlpDetector && dlpDetector->dlp_ref_cnt > 0) {
        dp_dlp_build_detector(dlpDetector);
    }

    dlpDetector = NULL;
    return 0;
}

int dpi_sig_bld_update_mac(dpi_dlpbld_mac_t *dlpbld_mac)
{
    int i;
    dpi_detector_t *dlp_detect_ptr = NULL;
    for (i = 0; i < dlpbld_mac->num_old_macs; i++) {
        dlp_detect_ptr = dpi_dlp_get_detector(&dlpbld_mac->old_mac_list[i]);
        if (dlp_detect_ptr) {
            break;
        }
    }
    if (dlp_detect_ptr == NULL) {
        DEBUG_ERROR(DBG_CTRL, "Missing existing dlp detector!!\n");
        return -1;
    }
    //add first before delete to avoid release detector tree prematurally
    for (i = 0; i < dlpbld_mac->num_add_macs; i++) {
        dpi_dlp_detect_add_mac(&dlpbld_mac->add_mac_list[i],dlp_detect_ptr);
    }

    for (i = 0; i < dlpbld_mac->num_del_macs; i++) {
        dpi_dlp_detect_release(&dlpbld_mac->del_mac_list[i]);
    }
    return 0;
}
    
