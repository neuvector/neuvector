#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "apis.h"
#include "debug.h"

extern io_callback_t g_callback;

uint32_t g_debug_levels = DBG_DEFAULT;

void debug_log_no_filter(bool print_ts, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    g_callback.debug(print_ts, fmt, args);
    va_end(args);
}

uint32_t debug_name2level(const char *name)
{
    if (strcasecmp(name, "all") == 0) {
        return (uint32_t)(-1);
    } else if (strcasecmp(name, "init") == 0) {
        return DBG_INIT;
    } else if (strcasecmp(name, "error") == 0) {
        return DBG_ERROR;
    } else if (strcasecmp(name, "ctrl") == 0) {
        return DBG_CTRL;
    } else if (strcasecmp(name, "packet") == 0) {
        return DBG_PACKET;
    } else if (strcasecmp(name, "session") == 0) {
        return DBG_SESSION;
    } else if (strcasecmp(name, "timer") == 0) {
        return DBG_TIMER;
    } else if (strcasecmp(name, "tcp") == 0) {
        return DBG_TCP;
    } else if (strcasecmp(name, "parser") == 0) {
        return DBG_PARSER;
    } else if (strcasecmp(name, "log") == 0) {
        return DBG_LOG;
    } else if (strcasecmp(name, "ddos") == 0) {
        return DBG_DDOS;
    } else if (strcasecmp(name, "policy") == 0) {
        return DBG_POLICY;
    } else if (strcasecmp(name, "dlp") == 0) {
        return DBG_DETECT;
    }

    return 0;
}

static char *action_name[] = {
[DPI_ACTION_NONE] = "NONE",
[DPI_ACTION_ALLOW] = "ALLOW",
[DPI_ACTION_DROP] = "DROP",
[DPI_ACTION_RESET] = "RESET",
[DPI_ACTION_BYPASS] = "BYPASS",
[DPI_ACTION_BLOCK] = "BLOCK",
};

const char *debug_action_name(int act)
{
    return action_name[act];
}
