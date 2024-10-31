#include <stdio.h>
#include <string.h>
#include "dpi/sig/dpi_sig.h"
#include "dpi/dpi_module.h"
#include "dpi/sig/dpi_search.h"

int dpi_sigopt_get_pcre (void *context, dpi_sig_context_class_t *c, uint8_t **pcre, uint32_t *hs_flags)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    dpi_sigopt_pcre_pattern_t *data = context;

    if (data->node.sigapi->type == DPI_SIGOPT_PCRE) {
        *pcre = data->pcre.string;
        *c = data->class;
        *hs_flags = data->pcre.hs_flags;
        return strlen((char*)(*pcre));
    } else {
        return 0;
    }
}

static dpi_sigopt_status_t dpi_sigopt_context_parser (char *value, dpi_sig_t *sig)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    dpi_sigopt_pcre_pattern_t *data;

    if (value == NULL) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    if (sig->last_pattern == NULL) {
        return DPI_SIGOPT_MISSING_OPTION;
    }

    data = sig->last_pattern;

    if (FLAGS_TEST(data->flags, DPI_SIGOPT_PAT_FLAG_CONTEXT_INUSE)) {
        return DPI_SIGOPT_DUP_OPTION;
    }

    if (strcasecmp(value, "url") == 0) {
        data->type = DPI_SIG_CONTEXT_TYPE_URI_ORIGIN;
        data->class = DPI_SIG_CONTEXT_CLASS_URI;
    } else if (strcasecmp(value, "header") == 0) {
        data->type = DPI_SIG_CONTEXT_TYPE_HEADER;
        data->class = DPI_SIG_CONTEXT_CLASS_HEADER;
    } else if (strcasecmp(value, "body") == 0) {
        data->type = DPI_SIG_CONTEXT_TYPE_BODY;
        data->class = DPI_SIG_CONTEXT_CLASS_BODY;
    } else if (strcasecmp(value, "packet") == 0) {
        data->type = DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN;
        data->class = DPI_SIG_CONTEXT_CLASS_PACKET;
    } else if (strcasecmp(value, "sql_query") == 0) {
        data->type = DPI_SIG_CONTEXT_TYPE_SQL_QUERY;
        data->class = DPI_SIG_CONTEXT_CLASS_BODY;
    } else {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    if (data->class == DPI_SIG_CONTEXT_CLASS_URI) {
        cds_list_del((struct cds_list_head *)data);
        cds_list_add_tail((struct cds_list_head *)data, &sig->uri_opts);
    } else if (data->class == DPI_SIG_CONTEXT_CLASS_HEADER) {
        cds_list_del((struct cds_list_head *)data);
        cds_list_add_tail((struct cds_list_head *)data, &sig->header_opts);
    } else if (data->class == DPI_SIG_CONTEXT_CLASS_BODY) {
        cds_list_del((struct cds_list_head *)data);
        cds_list_add_tail((struct cds_list_head *)data, &sig->body_opts);
    }

    FLAGS_SET(data->flags, DPI_SIGOPT_PAT_FLAG_CONTEXT_INUSE);
    return DPI_SIGOPT_OK;
}

dpi_sigopt_api_t SIGOPTContext = {
    .type = DPI_SIGOPT_CONTEXT,
    .parser = dpi_sigopt_context_parser,
};

dpi_sigopt_api_t *dpi_sigopt_context_register (void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    return &SIGOPTContext;
}

struct hs_context {
    int matched;
    int *found_offset;
};

static int dpi_sigopt_hs_callback(unsigned int id, unsigned long long from,
                              unsigned long long to, unsigned int flags,
                              void *ctx) {
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    struct hs_context *hsctx = ctx;

    hsctx->matched = 1;
    *(hsctx->found_offset) = (int)to; // safe, as buffer has int len

    return 1; // halt matching
}

// Return 1 when we find the pattern, 0 when we don't.
static int dpi_sigopt_hs_search(dpi_sigopt_pcre_pattern_t *data, const char *buf, int len,
                            int start_offset, int *found_offset, dpi_detector_t *detector)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    struct hs_context hsctx;
    hsctx.matched = 0;
    hsctx.found_offset = found_offset;

    // XXX: we currently ignore start_offset, which might be used to reduce the
    // size of the buffer being scanned. Need to be careful with anchors,
    // assertions etc.

    if (detector->dlp_hs_pcre_scan_scratch == NULL) {
        HyperscanActivatePcre((void *)detector);
        if (detector->dlp_hs_pcre_scan_scratch == NULL){
            DEBUG_DLP("detector->dlp_hs_pcre_scan_scratch(%p) not ready yet\n", detector->dlp_hs_pcre_scan_scratch);
            return 0;
        }
    }
    hs_error_t err = hs_scan(data->pcre.hs_db, buf, len, 0,
                             detector->dlp_hs_pcre_scan_scratch, dpi_sigopt_hs_callback, &hsctx);
    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
        // An error occurred, fall through to pcre
        DEBUG_LOG(DBG_DETECT, NULL, "hs_scan returned error %d\n", err);
        return 0;
    }

    if (hsctx.matched == 0) {
        // No matches, no need to run pcre.
        return 0;
    }

    return 1;
}


static int
dpi_sigopt_pcre_search (dpi_sigopt_pcre_pattern_t *data, dpi_packet_t *p,
                    dpi_sig_context_type_t t, dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    dpi_dlp_area_t *dlparea = &p->dlp_area[t];
    uint8_t *ptr;
    uint32_t len, offset;
    int ret = 0;
    pcre2_match_data * match_data;
    PCRE2_SIZE *ovector;
    int rc;
    int found_offset = -1;
    
    ptr = dlparea->dlp_ptr;
    len = dlparea->dlp_len;
    offset = dlparea->dlp_offset;
    
    // Prefilter with Hyperscan if available; if Hyperscan says the buffer
    // cannot match this PCRE, we can fall out here.
    if (data->pcre.hs_db) {
        int hs_match = dpi_sigopt_hs_search(data, (const char*)ptr, len, offset, &found_offset, (dpi_detector_t *)sig->detector);
        int is_prefiltering = data->pcre.hs_flags & HS_FLAG_PREFILTER;

        // If the pattern is inverted and we're not prefiltering AND
        // start_offset was zero, we don't have to do confirm in PCRE.
        if (FLAGS_TEST(data->flags, DPI_SIGOPT_PAT_FLAG_NEGATIVE)) {
            if (offset == 0 && !is_prefiltering) {
                return !hs_match;
            } else if (!hs_match) {
                // Hyperscan didn't match, so pcre_exec will not match, so
                // return that the INVERTED pcre did match.
                return 1;
            } else {
                // Hyperscan did match, we need to confirm with pcre as we're
                // prefiltering.
                goto pcre_confirm;
            }
        }

        // Note: we must do confirm in PCRE if a start_offset was specified.
        if (offset == 0) {
            if (data->pcre.hs_noconfirm || (!is_prefiltering)) {
                return hs_match; // No confirm necessary.
            }
        }

        if (!hs_match) {
            // No match in Hyperscan, so no PCRE match can occur.
            return 0;
        }

        // Otherwise, Hyperscan claims there might be a match. Fall through to
        // post-confirm with PCRE.
    }

pcre_confirm:

    //
    if(data->pcre.recompiled == NULL) {
        DEBUG_LOG(DBG_DETECT, p, "ERROR: PCRE2 signature is not compiled '%s'\n", data->pcre.string);
        return ret;
    } 
    match_data = pcre2_match_data_create_from_pattern(data->pcre.recompiled, NULL);
    
    if (match_data == NULL) {
        DEBUG_LOG(DBG_DETECT, p, "ERROR: PCRE2 match data block cannot be allocated\n");
        return ret;
    }
    rc = pcre2_match(data->pcre.recompiled, (PCRE2_SPTR)ptr, len, offset, 0, match_data, NULL);
    
    /* Matching failed: handle error cases */
    if (rc < 0) { 
        switch(rc){
            case PCRE2_ERROR_NOMATCH: 
                //DEBUG_LOG(DBG_DETECT, p, "PCRE2 Pattern does not match\n");
                break;
            default: 
                DEBUG_LOG(DBG_DETECT, p, "PCRE2 Matching error %d\n", rc);
                break;
        }
        ret = 0;
    } else {
        /* Match succeded. Get a pointer to the output vector, where string offsets are
        stored. */
        ovector = pcre2_get_ovector_pointer(match_data);
        DEBUG_LOG(DBG_DETECT, NULL, "Match succeeded between offset0 %d and offset1 %d\n", (int)ovector[0],(int)ovector[1]);
        found_offset = (int)ovector[1];
        p->dlp_match_seq = dlparea->dlp_start + dlparea->dlp_offset + found_offset;
        p->dlp_match_type = t;
        ret = 1;
    }
    pcre2_match_data_free(match_data);

    if (!FLAGS_TEST(data->flags, DPI_SIGOPT_PAT_FLAG_NEGATIVE)) {
        return ret;
    } else {
        return !ret;
    }
}

static int dpi_sigopt_pcre_handler (void *context, dpi_packet_t *pkt, dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    dpi_sigopt_pcre_pattern_t *data = context;
    dpi_sig_context_type_t t;

    t = (pkt->dlp_pat_context == DPI_SIG_CONTEXT_TYPE_MAX) ? data->type : pkt->dlp_pat_context;

    if ((data->pcre.hs_noconfirm || !(data->pcre.hs_flags & HS_FLAG_PREFILTER)) &&
        !(FLAGS_TEST(data->flags, DPI_SIGOPT_PAT_FLAG_NEGATIVE)) &&
        pkt->dlp_area[t].dlp_offset == 0) {
        return 1;
    }
    
    if (pkt->dlp_area[t].dlp_ptr != NULL && pkt->dlp_area[t].dlp_len > 0) {
        if (dpi_sigopt_pcre_search(data, pkt, t, sig)) {
            return 1;
        }
    }

    return 0;
}

static void dpi_sigopt_pcre_pattern_release (void *context)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    dpi_sigopt_pcre_pattern_t *data = context;

    if (data) {
        if (data->pcre.string) {
            free(data->pcre.string);
        }

        if (data->pcre.recompiled) {
            pcre2_code_free(data->pcre.recompiled);
        }
        
        if (data->pcre.hs_db) {
            hs_free_database(data->pcre.hs_db);
        }
        free(data);
    }
}

static int dpi_sigopt_hs_fixed_width(const char *re, unsigned int hs_flags) {
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);

    hs_expr_info_t *info = NULL;
    hs_compile_error_t *compile_error = NULL;

    hs_error_t err = hs_expression_info(re, hs_flags, &info, &compile_error);
    if (err != HS_SUCCESS) {
        DEBUG_LOG(DBG_DETECT, NULL, "fail to retrieve hs expression info\n");
        hs_free_compile_error(compile_error);
        return 0;
    }

    if (!info) {
        return 0;
    }

    int fixed_width = (info->min_width == info->max_width &&
            info->max_width != 0xffffffff);
    free(info);
    return fixed_width;
}

static dpi_sigopt_status_t dpi_sigopt_hsbuild(dpi_sigopt_pcre_pattern_t *data, const char *re,
                           int pcre_compile_flags, dpi_detector_t *detector) {
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);

    if (data == NULL || data->pcre.recompiled == NULL || re == NULL) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    /* Note that we also allow PCRE_UNGREEDY even though there is no Hyperscan
     * flag for it. Greedy/ungreedy semantics make no difference for the
     * prefilter use case, where the match offset reported by Hyperscan is not
     * used. */

    const int supported_pcre_flags =
        PCRE2_CASELESS | PCRE2_DOTALL | PCRE2_MULTILINE | PCRE2_UNGREEDY;
    if (pcre_compile_flags & ~supported_pcre_flags) {
        DEBUG_LOG(DBG_DETECT, NULL, "fail: PCRE2 '%s' unsupported flags=%d\n", 
                                data->pcre.string,
                                pcre_compile_flags & ~supported_pcre_flags);
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    int hs_flags = HS_FLAG_ALLOWEMPTY;
    if (pcre_compile_flags & PCRE2_CASELESS)
        hs_flags |= HS_FLAG_CASELESS;
    if (pcre_compile_flags & PCRE2_DOTALL)
        hs_flags |= HS_FLAG_DOTALL;
    if (pcre_compile_flags & PCRE2_MULTILINE)
        hs_flags |= HS_FLAG_MULTILINE;

    hs_error_t err;
    hs_compile_error_t *compile_error = NULL;

    /* First, we attempt to compile the pattern with full Hyperscan support. */
    err = hs_compile(re, hs_flags, HS_MODE_BLOCK, NULL, &data->pcre.hs_db,
                     &compile_error);
    if (err != HS_SUCCESS) {
        DEBUG_LOG(DBG_DETECT, NULL, "fail to compile hyperscan db due to unsupported PCRE!\n");
        data->pcre.hs_db = NULL;
        if (compile_error) {
            hs_free_compile_error(compile_error);
        }
    }

    /* If the first attempt failed, we use Hyperscan's prefiltering support to
     * attempt to build a simplified version of the pattern. */
    if (!data->pcre.hs_db) {
        hs_flags |= HS_FLAG_PREFILTER;
        err = hs_compile(re, hs_flags, HS_MODE_BLOCK, NULL, &data->pcre.hs_db,
                         &compile_error);
        if (err != HS_SUCCESS) {
            DEBUG_LOG(DBG_DETECT, NULL, "fail to compile hyperscan db in prefilter mode!\n");
            data->pcre.hs_db = NULL;
            if (compile_error) {
                hs_free_compile_error(compile_error);
            }
        }
    }

    if (!data->pcre.hs_db) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    data->pcre.hs_flags = hs_flags;

    // Ensure that the scratch region can handle this database.
    err = hs_alloc_scratch(data->pcre.hs_db, &detector->dlp_hs_pcre_build_scratch);
    if (err != HS_SUCCESS) {
        DEBUG_LOG(DBG_DETECT, NULL, "hs_alloc_scratch() failed: returned error %d\n", err);
        hs_free_database(data->pcre.hs_db);
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    uint32_t pcre_scratch_size = 0;
    err = hs_scratch_size(detector->dlp_hs_pcre_build_scratch, (size_t *)&pcre_scratch_size);
    if (err != HS_SUCCESS) {
        DEBUG_ERROR(DBG_DETECT,"pcre hs_scratch_size() failed: error %d\n", err);
        return DPI_SIGOPT_FAILED;
    }

    uint32_t pcre_db_size = 0;
    err = hs_database_size(data->pcre.hs_db, (size_t *)&pcre_db_size);
    if (err != HS_SUCCESS) {
        DEBUG_ERROR(DBG_DETECT,"pcre hs_database_size() failed: error %d\n", err);
        return DPI_SIGOPT_FAILED;
    }
    
    //DEBUG_LOG(DBG_DETECT,NULL, "Built Hyperscan database: %u bytes\n",pcre_db_size);
    
    // Update summary info.
    detector->dlp_pcre_hs_summary.db_count++;
    detector->dlp_pcre_hs_summary.db_bytes += pcre_db_size;
    detector->dlp_pcre_hs_summary.scratch_size = pcre_scratch_size;
    
    //DEBUG_LOG(DBG_DETECT, NULL, "Pcre hs db_count(%d) allocated, db_bytes(%u), scratch_size(%u)!\n",
    //detector->dlp_pcre_hs_summary.db_count,detector->dlp_pcre_hs_summary.db_bytes,detector->dlp_pcre_hs_summary.scratch_size);

    if (!(hs_flags & HS_FLAG_PREFILTER) && dpi_sigopt_hs_fixed_width(re, hs_flags)) {
        data->pcre.hs_noconfirm = 1;
    }
    return DPI_SIGOPT_OK;
}

static dpi_sigopt_status_t dpi_sigopt_pcre_parser (char *value, dpi_sig_t *sig)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);

    dpi_sigopt_pcre_pattern_t *data;
    uint8_t flags = 0;
    char *start, *end;
    char delimiter = '/';
    uint16_t pcre_flags = 0;
    int pcre_errno;
    PCRE2_SIZE pcre_erroroffset;

    if (value == NULL) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    if (sig->pcre_count >= DPI_MAX_PCRE_PATTERNS) {
        return DPI_SIGOPT_TOO_MANY_PCRE_PAT;
    }
    
    FLAGS_SET(flags, DPI_SIGOPT_PAT_FLAG_PCRE);

    start = value;
    if (*start == '!') {
        start ++;
        FLAGS_SET(flags, DPI_SIGOPT_PAT_FLAG_NEGATIVE);
        strip_str_quote(strip_str(start));
    }

    // if 'm' is used, the following character is treated as the delimiter
    if (*start == 'm') {
        start ++;
        if (*start == '\0') {
            return DPI_SIGOPT_INVALID_OPTION_VALUE;
        }
        delimiter = *start;
    } else if (*start != delimiter) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }
        
    end = strrchr(start, delimiter);
    if (end == NULL || end == start) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    data = calloc(1, sizeof(dpi_sigopt_pcre_pattern_t));
    if (data == NULL) {
        return DPI_SIGOPT_FAILED;
    }
    data->node.sigapi = dpi_sigopt_pcre_register();
    data->type = DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN;
    data->class = DPI_SIG_CONTEXT_CLASS_PACKET;
    data->flags = flags;

    start ++;
    *end = '\0';
    end ++;
    while (*end != '\0') {
        switch (*end) {
        case 'i':
            pcre_flags |= PCRE2_CASELESS;
            break;
        case 'm':
            pcre_flags |= PCRE2_MULTILINE;
            break;
        case 's':
            pcre_flags |= PCRE2_DOTALL;
            break;
        case 'x':
            pcre_flags |= PCRE2_EXTENDED;
            break;
        case 'A':
            pcre_flags |= PCRE2_ANCHORED;
            break;
        case 'E':
            pcre_flags |= PCRE2_DOLLAR_ENDONLY;
            break;
        case 'G':
            pcre_flags |= PCRE2_UNGREEDY;
            break;
        default:
            dpi_sigopt_pcre_pattern_release(data);
            return DPI_SIGOPT_INVALID_OPTION_VALUE;
        }

        end ++;
    }

    data->pcre.string = (uint8_t *)strdup(start);
    if (data->pcre.string == NULL) {
        dpi_sigopt_pcre_pattern_release(data);
        return DPI_SIGOPT_FAILED;
    }
    data->pcre.recompiled = pcre2_compile((PCRE2_SPTR)start,
                                            PCRE2_ZERO_TERMINATED,
                                            pcre_flags,
                                            &pcre_errno,
                                            &pcre_erroroffset,
                                            NULL);
    if(data->pcre.recompiled == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(pcre_errno, buffer, sizeof(buffer));
        DEBUG_LOG(DBG_DETECT, NULL, "ERROR: PCRE2 compilation for (%s) failed at offset %d: %s\n", 
                    start, pcre_errno, buffer);
        dpi_sigopt_pcre_pattern_release(data);
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    } 

    if (dpi_sigopt_hsbuild(data,start, pcre_flags, (dpi_detector_t *)sig->detector) == DPI_SIGOPT_INVALID_OPTION_VALUE) {
        if (data->pcre.hs_db != NULL) {
            hs_free_database(data->pcre.hs_db);
            data->pcre.hs_db = NULL;
        }
        DEBUG_LOG(DBG_DETECT, NULL, "Fail to compile hyperscan db but pcre2_compile is successful, still ok!\n");
        //return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    cds_list_add_tail((struct cds_list_head *)data, &sig->packet_opts);

    sig->last_pattern = data;
    sig->pcre_count ++;
    return DPI_SIGOPT_OK;
}

dpi_sigopt_api_t SIGOPTIONPcre = {
    .type = DPI_SIGOPT_PCRE,
    .parser = dpi_sigopt_pcre_parser, 
    .handler = dpi_sigopt_pcre_handler,
    .release = dpi_sigopt_pcre_pattern_release,
};

dpi_sigopt_api_t *dpi_sigopt_pcre_register (void)
{
    //DEBUG_LOG_FUNC_ENTRY(DBG_DETECT, NULL);
    return &SIGOPTIONPcre;
}
