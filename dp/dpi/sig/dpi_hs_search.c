#include "dpi/dpi_module.h"
#include "dpi/sig/dpi_hyperscan_common.h"
#include "dpi/sig/dpi_search.h"

#define INITIAL_PATTERN_ARRAY_ALLOC_SIZE 10

extern void dpi_dlp_add_candidate(dpi_packet_t *p, dpi_sig_t *sig, bool nc);

#define DFA_LONGEST_USEFULL_PATTERN 16

static dpi_hyperscan_pm_t *dpi_hs_create()
{
    dpi_hyperscan_pm_t *pm = (dpi_hyperscan_pm_t *) calloc(1, sizeof(dpi_hyperscan_pm_t));

    if (!pm) {
        DEBUG_LOG(DBG_DETECT, NULL, "Unable to allocate memory for hyperscan pattern match!\n");
        return NULL;
    } 
    pm->hs_patterns_cap = INITIAL_PATTERN_ARRAY_ALLOC_SIZE;
    pm->hs_patterns = calloc(1, sizeof(dpi_hyperscan_pattern_t) * pm->hs_patterns_cap);
    if (!pm->hs_patterns) {
        DEBUG_LOG(DBG_DETECT, NULL, "Unable to allocate memory for hyperscan pattern match sigature!\n");
        free(pm);
        return NULL;
    } 

    return pm;
}

static void
dpi_dlp_hs_add_pattern (dpi_hyperscan_pm_t *hspm, uint8_t *pcre_pat, int patlen, uint32_t hs_flags, dpi_sig_assoc_t *sa)
{
    if (!hspm) {
        return;
    }

    // Reallocate patterns array if it's at capacity.
    if (hspm->hs_patterns_num + 1 > hspm->hs_patterns_cap) {
        uint32_t growth = hspm->hs_patterns_cap / 2 > 0 ? hspm->hs_patterns_cap / 2 : 1;
        hspm->hs_patterns_cap += growth;
        dpi_hyperscan_pattern_t *tmp = calloc(1, sizeof(dpi_hyperscan_pattern_t) * hspm->hs_patterns_cap);
        if (!tmp) {
            return;
        }
        memcpy(tmp, hspm->hs_patterns, sizeof(dpi_hyperscan_pattern_t) * hspm->hs_patterns_num);
        free(hspm->hs_patterns);
        hspm->hs_patterns = tmp;
    }

    dpi_hyperscan_pattern_t *hp = &hspm->hs_patterns[hspm->hs_patterns_num];
    hp->pattern = (char *)calloc(patlen+1, sizeof(char));
    if (hp->pattern == NULL) {
        return;
    }
    hp->pattern_len = strlcpy(hp->pattern, (const char *)pcre_pat, patlen+1);
    hp->hs_flags = hs_flags;
    hp->pattern_idx = hspm->hs_patterns_num++;
    memcpy(&hp->hs_sa, sa, sizeof(dpi_sig_assoc_t));
}

int dpi_dlp_hs_compile(dpi_hyperscan_pm_t *hspm, dpi_detector_t *detector) {

    if (!hspm || hspm->hs_patterns_num == 0) {
        return -1;
    }

    // The Hyperscan compiler takes its patterns in a group of arrays.
    uint32_t num_patterns;
    char **patterns;
    uint32_t *flags;
    uint32_t *ids;
    uint32_t i;

    num_patterns = hspm->hs_patterns_num;
    patterns = (char **)calloc(num_patterns, sizeof(char *));
    if (!patterns) {
        DEBUG_ERROR(DBG_DETECT, "Out of memory, patterns cannot be allocated!\n");
        return -1;
    }

    flags = (uint32_t *)calloc(num_patterns, sizeof(uint32_t));
    if (!flags) {
        DEBUG_ERROR(DBG_DETECT, "Out of memory, flags cannot be allocated!\n");
        free(patterns);
        return -1;
    }
    
    ids = (uint32_t *)calloc(num_patterns, sizeof(uint32_t));
    if (!ids) {
        DEBUG_ERROR(DBG_DETECT, "Out of memory, ids cannot be allocated!\n");
        free(patterns);
        free(flags);
        return -1;
    }
    
    for (i=0; i < num_patterns; i++) {
        dpi_hyperscan_pattern_t *hp = &hspm->hs_patterns[i];
        patterns[i] = hp->pattern;
        flags[i] = hp->hs_flags;
        flags[i] |= HS_FLAG_SINGLEMATCH;
        ids[i] = i;
    }

    hs_compile_error_t *compile_error = NULL;
    hs_error_t error = hs_compile_multi((const char **)patterns, flags, ids, num_patterns, HS_MODE_BLOCK, NULL, &(hspm->db), &compile_error);

    free(patterns);
    free(flags);
    free(ids);

    if (compile_error != NULL) {
        DEBUG_ERROR(DBG_DETECT,"hs_compile_multi() failed: %s (expression: %d)\n",
                   compile_error->message, compile_error->expression);
        hs_free_compile_error(compile_error);
        return -1;
    }

    if (error != HS_SUCCESS) {
        DEBUG_ERROR(DBG_DETECT,"hs_compile_multi() failed: error %d\n", error);
        return -1;
    }

    // Ensure the per detector Hyperscan scratch space has seen this database.
    error = hs_alloc_scratch(hspm->db, &detector->dlp_hs_mpse_build_scratch);

    if (error != HS_SUCCESS) {
        DEBUG_ERROR(DBG_DETECT,"hs_alloc_scratch() failed: error %d\n", error);
        return -1;
    }

    uint32_t scratch_size = 0;
    error = hs_scratch_size(detector->dlp_hs_mpse_build_scratch, (size_t *)&scratch_size);
    if (error != HS_SUCCESS) {
        DEBUG_ERROR(DBG_DETECT,"hs_scratch_size() failed: error %d\n", error);
        return -1;
    }

    uint32_t db_size = 0;
    error = hs_database_size(hspm->db, (size_t *)&db_size);
    if (error != HS_SUCCESS) {
        DEBUG_ERROR(DBG_DETECT,"hs_database_size() failed: error %d\n", error);
        return -1;
    }

    //DEBUG_LOG(DBG_DETECT,NULL, "Built Hyperscan database: %u patterns, %u bytes\n",
    //                        num_patterns, db_size);

    // Update summary info.
    detector->dlp_hs_summary.db_count++;
    detector->dlp_hs_summary.db_bytes += db_size;
    detector->dlp_hs_summary.scratch_size = scratch_size;

    //DEBUG_LOG(DBG_DETECT, NULL, "Total (%d) hyperscan db allocated, db_bytes(%u), scratch_size(%u)!\n",
    //detector->dlp_hs_summary.db_count, detector->dlp_hs_summary.db_bytes, detector->dlp_hs_summary.scratch_size);
    return 0;
}

static void dpi_dlp_hs_search_init (void *detector)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT,NULL);
    HyperscanActivate(detector);
}

static void *dpi_dlp_hs_search_create (void)
{
    dpi_hs_search_t *hs_search = calloc(1, sizeof(dpi_hs_search_t));

    if (hs_search != NULL) {
        dpi_sig_context_class_t c;

        for (c = 0; c < DPI_SIG_CONTEXT_CLASS_MAX; c ++) {
            hs_search->data[c].hs_pm = dpi_hs_create();
            CDS_INIT_LIST_HEAD(&hs_search->data[c].nc_sigs);
        } 
    }

    return hs_search;
}


static void dpi_dlp_add_nc_dlprule (struct cds_list_head *list, dpi_sig_t *sig)
{
    dpi_sig_node_t *node = (dpi_sig_node_t *)calloc(1, sizeof(dpi_sig_node_t));

    if (node != NULL) {
        node->sig = sig;
        cds_list_add_tail((struct cds_list_head *)node, list);
    }

    return;
}

static void dpi_dlp_hs_search_add_dlprule (void *context, dpi_sig_t *sig)
{
    dpi_hs_search_t *hs_search = context;

    hs_search->count ++;

    if (sig->hs_count > 0) {
        int i;

        for (i = 0; i < sig->hs_count; i ++) {
            dpi_sig_context_class_t c;
            int pcre_len;
            uint8_t *pcre_pat;
            uint32_t hs_flags;
            dpi_sig_assoc_t sa;

            pcre_len = dpi_sigopt_get_pcre(sig->hs_pats[i], &c, &pcre_pat, &hs_flags);
            sa.sig = sig;
            sa.dlptbl_idx = hs_search->count - 1;
            sa.dpa_mask = (~(1 << i)) & ((1 << sig->hs_count) - 1);

            switch (c) {
            case DPI_SIG_CONTEXT_CLASS_URI:
                dpi_dlp_hs_add_pattern(hs_search->data[c].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                break;
            case DPI_SIG_CONTEXT_CLASS_HEADER:
                dpi_dlp_hs_add_pattern(hs_search->data[c].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                break;
            case DPI_SIG_CONTEXT_CLASS_BODY:
                dpi_dlp_hs_add_pattern(hs_search->data[c].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                break;
            case DPI_SIG_CONTEXT_CLASS_PACKET:
                dpi_dlp_hs_add_pattern(hs_search->data[DPI_SIG_CONTEXT_CLASS_URI].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                dpi_dlp_hs_add_pattern(hs_search->data[DPI_SIG_CONTEXT_CLASS_HEADER].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                dpi_dlp_hs_add_pattern(hs_search->data[DPI_SIG_CONTEXT_CLASS_BODY].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                dpi_dlp_hs_add_pattern(hs_search->data[DPI_SIG_CONTEXT_CLASS_PACKET].hs_pm, pcre_pat, pcre_len, hs_flags, &sa);
                break;
            default:
                break;
            }
        }
    } else {
        if (!cds_list_empty(&sig->uri_opts)) {
            dpi_dlp_add_nc_dlprule(&hs_search->data[DPI_SIG_CONTEXT_CLASS_URI].nc_sigs, sig);
        } else if (!cds_list_empty(&sig->header_opts)) {
            dpi_dlp_add_nc_dlprule(&hs_search->data[DPI_SIG_CONTEXT_CLASS_HEADER].nc_sigs, sig);
        } else if (!cds_list_empty(&sig->body_opts)) {
            dpi_dlp_add_nc_dlprule(&hs_search->data[DPI_SIG_CONTEXT_CLASS_BODY].nc_sigs, sig);
        } else {
            dpi_dlp_add_nc_dlprule(&hs_search->data[DPI_SIG_CONTEXT_CLASS_NC].nc_sigs, sig);
        }
    }
}


static void dpi_dlp_hs_search_compile (void *context)
{
    dpi_hs_search_t *hs_search = context;
    dpi_sig_context_class_t c;
    int i, j;    

    hs_search->dlptbls = calloc(MAX_DP_THREADS, sizeof(dlptbl_t));
    if (hs_search->dlptbls == NULL) {
        return;
    }
    
    for (i = 0; i < MAX_DP_THREADS; i ++) {
        hs_search->dlptbls[i].tbl = calloc(hs_search->count, sizeof(dlptbl_node_t));
        if (hs_search->dlptbls[i].tbl == NULL) {
            for (j = i - 1; j >= 0; j --) {
                free(hs_search->dlptbls[j].tbl);
            }
            break;
        }
    }    

    for (c = 0; c < DPI_SIG_CONTEXT_CLASS_MAX; c ++) {
        dpi_dlp_hs_compile(hs_search->data[c].hs_pm, hs_search->detector);
    }
}

int dpi_dlp_hs_proc_sa (dpi_hs_search_t *hs_search, dpi_sig_assoc_t *sa, dpi_packet_t *p)
{
    uint32_t proc_id = THREAD_ID;
    dlptbl_node_t *dlptbl = hs_search->dlptbls[proc_id].tbl;
    uint32_t dlpdet_id = th_hs_detect_id;

    dlptbl_node_t *node;
    bool add_candidate = false;

    if(sa == NULL || hs_search == NULL) {
        return 0;
    }

    node = &(dlptbl[sa->dlptbl_idx]);

    if (node->dlpdet_id != dlpdet_id) {
        node->dlpdet_id = dlpdet_id;
        node->dlpat_arr = sa->dpa_mask;
        add_candidate = (0 == node->dlpat_arr);
    } else {
        if (node->dlpat_arr) {
            node->dlpat_arr &= sa->dpa_mask;
            add_candidate = (0 == node->dlpat_arr);
        }
    }

    if (add_candidate) {
        dpi_dlp_add_candidate(p, sa->sig, false);
        return 1;
    }

    return 0;
}

typedef struct dpi_hs_callback_context_ {
    dpi_hs_search_t **hs_search;
    dpi_hyperscan_pm_t *pm;
    dpi_packet_t **pkt;
    int (*proc_sa)(dpi_hs_search_t *hs_search, dpi_sig_assoc_t *sa, dpi_packet_t *p);
} dpi_hs_callback_context_t;

static
int dpi_dlp_hs_onmatch(unsigned int id, unsigned long long from, unsigned long long to,
            unsigned int flags, void *hs_ctx) {

    dpi_hs_callback_context_t *ctx = hs_ctx;
    dpi_hyperscan_pattern_t *hp = &ctx->pm->hs_patterns[id];

    if (ctx->proc_sa(*(ctx->hs_search), &hp->hs_sa, *(ctx->pkt)) > 0) {
        return 0; // even after a match cannot Halt matching, because multiple sig can be built in same hsdb
    }

    return 0; // Continue matching.
}

static void
dpi_dlp_hsdb_detect (dpi_hs_search_t *hs_search, dpi_packet_t *p, dpi_sig_context_type_t t)
{
    dpi_sig_context_class_t c = dpi_dlp_ctxt_type_2_cat(t);
    struct cds_list_head *nc_list;
    uint32_t len = p->dlp_area[t].dlp_len;
    uint8_t *buf = p->dlp_area[t].dlp_ptr;
    dpi_sig_node_t *sig_node_itr, *sig_node_next;
    dpi_hs_callback_context_t ctx;
    hs_error_t error;
    dpi_detector_t *detector = hs_search->detector;

    nc_list = &hs_search->data[c].nc_sigs;
    
    cds_list_for_each_entry_safe(sig_node_itr, sig_node_next, nc_list, node) {
        dpi_dlp_add_candidate(p, sig_node_itr->sig, true);
    }

    if (hs_search->data[c].hs_pm == NULL || hs_search->data[c].hs_pm->db == NULL) {    
        return;
    }
    ctx.hs_search = &hs_search;
    ctx.pm = hs_search->data[c].hs_pm;
    ctx.pkt = &p;
    ctx.proc_sa = dpi_dlp_hs_proc_sa;

    if (detector->dlp_hs_mpse_scan_scratch == NULL) {
        HyperscanActivateMpse((void *)detector);
        if (detector->dlp_hs_mpse_scan_scratch == NULL) {
            DEBUG_LOG(DBG_DETECT,NULL, "detector->dlp_hs_mpse_scan_scratch(%p) not ready yet\n", detector->dlp_hs_mpse_scan_scratch);
            return;
        }
    }

    error = hs_scan(hs_search->data[c].hs_pm->db, (const char *)buf, len, 0,
                               detector->dlp_hs_mpse_scan_scratch, dpi_dlp_hs_onmatch, &ctx);

    if (error != HS_SUCCESS && error != HS_SCAN_TERMINATED) {
        DEBUG_LOG(DBG_DETECT,NULL, "hs_scan() failed: error %d\n", error);
    }
}

static void dpi_dlp_hs_search_detect (void *context, void *packet)
{
    dpi_hs_search_t *hs_search = context;
    dpi_packet_t *p = (dpi_packet_t *)packet;
    struct cds_list_head *nc_list;
    bool skip_packet = false;
    uint32_t proc_id = THREAD_ID;
    dlptbl_node_t *dlptbl = hs_search->dlptbls[proc_id].tbl;
    dpi_sig_node_t *sig_node_itr, *sig_node_next;

    if (dlptbl == NULL) {
        return;
    }

    th_hs_detect_id ++;
    if (th_hs_detect_id == DPI_HS_DETECTION_MAX) {
        memset(dlptbl, 0, hs_search->count * sizeof(dlptbl_node_t));
        th_hs_detect_id = 1;
    }

    if (p->dlp_area[DPI_SIG_CONTEXT_TYPE_URI_ORIGIN].dlp_len > 0) {
        dpi_dlp_hsdb_detect(hs_search, p, DPI_SIG_CONTEXT_TYPE_URI_ORIGIN);
        skip_packet = true;
    }

    if (p->dlp_area[DPI_SIG_CONTEXT_TYPE_HEADER].dlp_len > 0) {
        dpi_dlp_hsdb_detect(hs_search, p, DPI_SIG_CONTEXT_TYPE_HEADER);
        skip_packet = true;
    }

    if (p->dlp_area[DPI_SIG_CONTEXT_TYPE_BODY].dlp_len > 0) {
        dpi_dlp_hsdb_detect(hs_search, p, DPI_SIG_CONTEXT_TYPE_BODY);
        skip_packet = true;
    }
    
    if (!skip_packet && p->dlp_area[DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN].dlp_len > 0) {
        dpi_dlp_hsdb_detect(hs_search, p, DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN);
    }

    nc_list = &hs_search->data[DPI_SIG_CONTEXT_CLASS_NC].nc_sigs;
    
    cds_list_for_each_entry_safe(sig_node_itr, sig_node_next, nc_list, node) {
        dpi_dlp_add_candidate(p, sig_node_itr->sig, true);
    }
}

static void release_hs_pm (dpi_hyperscan_pm_t *hs_pm)
{
    uint32_t num;

    if (!hs_pm) {
        return;
    }

    if(hs_pm->hs_patterns) {
        for (num = 0; num < hs_pm->hs_patterns_num; num++) {
            if (hs_pm->hs_patterns[num].pattern) {
                free(hs_pm->hs_patterns[num].pattern);
            }
        }
        free(hs_pm->hs_patterns);
    }
    
    if (hs_pm->db)
        hs_free_database(hs_pm->db);
    free(hs_pm);
}

static void release_nc_dlprules (struct cds_list_head *list)
{
    dpi_sig_node_t *sig_node_itr, *sig_node_next;
    cds_list_for_each_entry_safe(sig_node_itr, sig_node_next, list, node) {
        cds_list_del((struct cds_list_head *)sig_node_itr);
        free(sig_node_itr);
    }
}

static void dpi_dlp_hs_search_release (void *context)
{
    int i;
    dpi_hs_search_t *hs_search = context;
    dpi_sig_context_class_t c;

    if (hs_search == NULL) {
        return;
    }

    for (c = 0; c < DPI_SIG_CONTEXT_CLASS_MAX; c ++) {
        release_hs_pm(hs_search->data[c].hs_pm);
        release_nc_dlprules(&hs_search->data[c].nc_sigs);
    }
    
    for (i = 0; i < MAX_DP_THREADS; i ++) {
        if (hs_search->dlptbls[i].tbl) {
            free(hs_search->dlptbls[i].tbl);
        }
    }
    
    free(hs_search->dlptbls);

    free(hs_search);
    
}


static dpi_sig_search_api_t DPI_HS_Search = {
    .init = dpi_dlp_hs_search_init,
    .create = dpi_dlp_hs_search_create,
    .add_sig = dpi_dlp_hs_search_add_dlprule,
    .compile = dpi_dlp_hs_search_compile,
    .detect = dpi_dlp_hs_search_detect,
    .release = dpi_dlp_hs_search_release,
};

dpi_sig_search_api_t *dpi_dlp_hs_search_register (void)
{
    return &DPI_HS_Search;
}


