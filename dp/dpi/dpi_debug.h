#ifndef __DPI_DEBUG_H__
#define __DPI_DEBUG_H__

#define debug_log_no_filter debug_log

#include "debug.h"

#define IF_DEBUG_LOG(level, p) \
        if (unlikely((g_debug_levels & (level)) && debug_log_packet_filter(p)))

#define DEBUG_LOG_NO_FILTER(format, args...) \
        debug_log(true, "%s: "format, __FUNCTION__, ##args)

#define DEBUG_LOG(level, p, format, args...) \
        IF_DEBUG_LOG(level, p) { DEBUG_LOG_NO_FILTER(format, ##args); }

#define DEBUG_LOG_FUNC_ENTRY(level, p) \
        IF_DEBUG_LOG(level, p) { DEBUG_LOG_NO_FILTER("enter\n"); }

void debug_log(bool print_ts, const char *fmt, ...);
bool debug_log_packet_filter(const dpi_packet_t *p);

void debug_dump_hex(const uint8_t *ptr, int len);
void debug_dump_packet(const dpi_packet_t *p);
void debug_dump_packet_short(const dpi_packet_t *p);
void debug_dump_session(const dpi_session_t *s);
void debug_dump_session_short(const dpi_session_t *s);

#endif
