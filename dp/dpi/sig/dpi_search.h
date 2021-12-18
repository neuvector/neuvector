#ifndef __DPI_SEARCH_H__
#define __DPI_SEARCH_H__

#include "dpi/sig/dpi_sig.h"
#include "utils/helper.h"
#include "dpi/dpi_module.h"
#include "dpi/sig/dpi_hyperscan.h"

typedef struct dpi_sig_search_ {
    uint32_t count;

    void *context;
    dpi_sig_search_api_t *search_api;
} dpi_sig_search_t;

typedef struct dpi_sig_service_tree_ {
    uint32_t count;
    dpi_sig_search_t client_server;
} dpi_sig_service_tree_t;

typedef struct dpi_sig_protocol_tree_ {
    uint32_t count;
    dpi_sig_service_tree_t service_unknown;
} dpi_sig_protocol_tree_t;

typedef struct dpi_sig_detect_tree_ {
    uint32_t count;
    dpi_sig_protocol_tree_t protocol_unknown;
} dpi_sig_detect_tree_t;

typedef struct dpi_detector_ {
    uint32_t pat_count, dpi_act_count;//, eng_count, non_hidden_pat_count;
    dpi_sig_detect_tree_t *tree;
    struct cds_list_head dlpSigList;
    hs_scratch_t *dlp_hs_mpse_build_scratch;
    hs_scratch_t *dlp_hs_mpse_scan_scratch;
    hs_scratch_t *dlp_hs_pcre_build_scratch;
    hs_scratch_t *dlp_hs_pcre_scan_scratch;
    dpi_hs_summary_t dlp_pcre_hs_summary;
    dpi_hs_summary_t dlp_hs_summary;
    uint16_t dlp_ref_cnt;
    uint16_t dlp_ver;
    //int def_action;
    int dlp_apply_dir;
} dpi_detector_t;

typedef struct dpi_hs_class_ {
    dpi_hyperscan_pm_t *hs_pm;
    struct cds_list_head nc_sigs;
} dpi_hs_class_t;
typedef struct dpi_sig_node_ {
    struct cds_list_head node;

    dpi_sig_t *sig;
} dpi_sig_node_t;

#define DPI_HS_DETECTION_MAX 0x1000000
typedef struct dlptbl_node_ {
    u_int32_t dlpdet_id : 24,
              dlpat_arr : 8;
} dlptbl_node_t;

typedef struct dlptbl_ {
    dlptbl_node_t *tbl;
} dlptbl_t;

typedef struct dpi_hs_search_ {
    uint32_t count;
    struct dpi_hs_class_ data[DPI_SIG_CONTEXT_CLASS_MAX];

    dlptbl_t *dlptbls;
    dpi_detector_t *detector;
} dpi_hs_search_t;

void dpi_build_dlp_tree (dpi_detector_t *dlp_detector);
bool dpi_dlp_ep_policy_check(dpi_packet_t *p);
bool dpi_waf_ep_policy_check(dpi_packet_t *p);
bool dpi_process_detector(dpi_packet_t *p);
void dpi_set_pkt_decision(dpi_packet_t *p, int action);
void dpi_dlp_init_hs_search (void *detector);
void dpi_dlp_release_detector (dpi_detector_t *detector);
void dpi_dlp_detector_destroy(dpi_detector_t *detector);
void dpi_dlp_release_dlprulelist (dpi_detector_t *detector);
void dpi_print_siglist(dpi_detector_t *detector);
void dpi_hs_free_global_context(dpi_detector_t *detector);
extern dpi_detector_t *g_release_detector;
extern dpi_detector_t *g_build_detector;

#endif
