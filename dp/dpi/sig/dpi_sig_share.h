#ifndef __DPI_SIG_SHARE_H__
#define __DPI_SIG_SHARE_H__

typedef enum dpi_sigopt_status_ {
    DPI_SIGOPT_OK = 0,
    DPI_SIGOPT_FAILED,
    DPI_SIGOPT_INVALID_SIG_NAME,
    DPI_SIGOPT_UNKNOWN_OPTION,
    DPI_SIGOPT_MISSING_OPTION,
    DPI_SIGOPT_DUP_OPTION,
    DPI_SIGOPT_INVALID_OPTION_VALUE,
    DPI_SIGOPT_VALUE_TOO_LONG,
    DPI_SIGOPT_TOO_MANY_DLP_RULE,
    DPI_SIGOPT_INVALID_USER_SIG_ID,
    DPI_SIGOPT_TOO_MANY_PCRE_PAT,
} dpi_sigopt_status_t;

typedef struct dpi_sig_config_ {
    char *name, *description, *text;
    uint32_t id;
    uint16_t flags;
    uint8_t severity;
    uint8_t action;
    uint32_t key;         
} dpi_sig_config_t;

#endif
