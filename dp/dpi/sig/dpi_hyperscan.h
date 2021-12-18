#ifndef __DPI_HYPERSCAN_H__
#define __DPI_HYPERSCAN_H__

#include <hs/hs.h>

typedef struct dpi_sig_assoc_ {

    dpi_sig_t *sig;
    uint16_t dlptbl_idx;
    uint8_t dpa_mask;
} dpi_sig_assoc_t;

typedef struct dpi_hyperscan_pattern_ {
    char *pattern;
    uint32_t pattern_len;
    uint32_t pattern_idx; /* actual pattern id */
    uint32_t hs_flags;
    dpi_sig_assoc_t hs_sa;
} dpi_hyperscan_pattern_t;

typedef struct dpi_hyperscan_pm_ {
    hs_database_t *db;
    dpi_hyperscan_pattern_t *hs_patterns;
    uint32_t hs_patterns_num; // number of elements
    uint32_t hs_patterns_cap; // allocated capacity
} dpi_hyperscan_pm_t;
#endif
