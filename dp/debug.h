#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <stdint.h>

#define DBG_MAC_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"
#define DBG_MAC_TUPLE(mac) \
        ((uint8_t *)&(mac))[0], ((uint8_t *)&(mac))[1], ((uint8_t *)&(mac))[2], \
        ((uint8_t *)&(mac))[3], ((uint8_t *)&(mac))[4], ((uint8_t *)&(mac))[5]
#define DBG_IPV4_FORMAT "%u.%u.%u.%u"
#define DBG_IPV4_TUPLE(ip) \
        ((uint8_t *)&(ip))[0], ((uint8_t *)&(ip))[1], \
        ((uint8_t *)&(ip))[2], ((uint8_t *)&(ip))[3]
#define DBG_IPV6_FORMAT "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x"
#define DBG_IPV6_TUPLE(ip) \
        ((uint8_t *)&(ip))[0], ((uint8_t *)&(ip))[1], \
        ((uint8_t *)&(ip))[2], ((uint8_t *)&(ip))[3], \
        ((uint8_t *)&(ip))[4], ((uint8_t *)&(ip))[5], \
        ((uint8_t *)&(ip))[6], ((uint8_t *)&(ip))[7], \
        ((uint8_t *)&(ip))[8], ((uint8_t *)&(ip))[9], \
        ((uint8_t *)&(ip))[10], ((uint8_t *)&(ip))[11], \
        ((uint8_t *)&(ip))[12], ((uint8_t *)&(ip))[13], \
        ((uint8_t *)&(ip))[14], ((uint8_t *)&(ip))[15]

#define DBG_ENUM_INIT    0
#define DBG_ENUM_ERROR   1
#define DBG_ENUM_CTRL    2
#define DBG_ENUM_PACKET  3
#define DBG_ENUM_SESSION 4
#define DBG_ENUM_TIMER   5
#define DBG_ENUM_TCP     6
#define DBG_ENUM_PARSER  7
#define DBG_ENUM_LOG     8
#define DBG_ENUM_DDOS    9
#define DBG_ENUM_POLICY  10
#define DBG_ENUM_DETECT  11

#define DBG_INIT    (1 << DBG_ENUM_INIT)
#define DBG_ERROR   (1 << DBG_ENUM_ERROR)
#define DBG_CTRL    (1 << DBG_ENUM_CTRL)
#define DBG_PACKET  (1 << DBG_ENUM_PACKET)
#define DBG_SESSION (1 << DBG_ENUM_SESSION)
#define DBG_TIMER   (1 << DBG_ENUM_TIMER)
#define DBG_TCP     (1 << DBG_ENUM_TCP)
#define DBG_PARSER  (1 << DBG_ENUM_PARSER)
#define DBG_LOG     (1 << DBG_ENUM_LOG)
#define DBG_DDOS    (1 << DBG_ENUM_DDOS)
#define DBG_POLICY  (1 << DBG_ENUM_POLICY)
#define DBG_DETECT  (1 << DBG_ENUM_DETECT)

#define DBG_DEFAULT (DBG_INIT|DBG_ERROR)

extern uint32_t g_debug_levels;

#define IF_DEBUG(level) \
        if (unlikely(g_debug_levels & (level)))

#define DEBUG_LEVEL(level, format, args...) \
        IF_DEBUG(level) { debug_log_no_filter(true, "%s: "format, __FUNCTION__,  ##args); }
#define DEBUG_ERROR(level, format, args...) \
        IF_DEBUG(level | DBG_ERROR) { debug_log_no_filter(true, "%s: "format, __FUNCTION__,  ##args); }
#define DEBUG_INIT(format, args...) \
        IF_DEBUG(DBG_INIT) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }
#define DEBUG_CTRL(format, args...) \
        IF_DEBUG(DBG_CTRL) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }
#define DEBUG_PACKET(format, args...) \
        IF_DEBUG(DBG_PACKET) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }
#define DEBUG_LOGGER(format, args...) \
        IF_DEBUG(DBG_LOG) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }
#define DEBUG_TIMER(format, args...) \
        IF_DEBUG(DBG_TIMER) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }

#define DEBUG_POLICY(format, args...) \
        IF_DEBUG(DBG_POLICY) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }

#define DEBUG_DLP(format, args...) \
        IF_DEBUG(DBG_DETECT) { debug_log_no_filter(true, "%s: "format, __FUNCTION__, ##args); }
        
#define DEBUG_FUNC_ENTRY(level) \
        IF_DEBUG(level) { debug_log_no_filter(true, "%s: enter\n", __FUNCTION__); }

void debug_log_no_filter(bool print_ts, const char *fmt, ...);
uint32_t debug_name2level(const char *name);

const char *debug_action_name(int act);
time_t get_current_time();
#endif
