#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "utils/helper.h"
#include "dpi/sig/dpi_sig.h"
#include "dpi/dpi_module.h"

#define DPI_DLIMTS "<>()#\"'"

static dpi_sigopt_status_t dpi_sigopt_sig_id_parser (char *value, dpi_sig_t *sig)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    if (value == NULL) {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    if (dpi_sig_has_option(sig, DPI_SIGOPT_SIG_ID)) {
        return DPI_SIGOPT_DUP_OPTION;
    }

    sig->sig_id = strtoul(value, (char **)NULL, 10);;
    sig->conf->id = sig->sig_id;

    return DPI_SIGOPT_OK;
}

static dpi_sigopt_api_t SIGOPTSigID = {
    .type = DPI_SIGOPT_SIG_ID,
    .parser = dpi_sigopt_sig_id_parser,
};

dpi_sigopt_api_t *dpi_sigopt_sig_id_register (void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    return &SIGOPTSigID;
}

static dpi_sigopt_status_t dpi_sigopt_name_parser (char *value, dpi_sig_t *sig)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    char *p;

    if (dpi_sig_has_option(sig, DPI_SIGOPT_NAME)) {
        return DPI_SIGOPT_DUP_OPTION;
    }

    if (value == NULL || value[0] == '\0') {
        return DPI_SIGOPT_INVALID_OPTION_VALUE;
    }

    if (value[0] == '\0' || strlen(value) != strlen(strip_str(value))) {
        return DPI_SIGOPT_INVALID_SIG_NAME;
    }

    p = value;
    strsep(&p, DPI_DLIMTS);
    if (p != NULL) {
        return DPI_SIGOPT_INVALID_SIG_NAME;
    }

    if (strlen(value) >= MAX_SIG_NAME_LEN) {
        return DPI_SIGOPT_VALUE_TOO_LONG;
    }

    if (sig->conf->name == NULL) {
        sig->conf->name = strdup(value);
        if (sig->conf->name == NULL) {
            return DPI_SIGOPT_FAILED;
        }
    }

    return DPI_SIGOPT_OK;
}

static dpi_sigopt_api_t SIGOPTName = {
    .type = DPI_SIGOPT_NAME,
    .parser = dpi_sigopt_name_parser,
};

dpi_sigopt_api_t *dpi_sigopt_name_register (void)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_DETECT,NULL);
    return &SIGOPTName;
}
