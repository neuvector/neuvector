#ifndef __DPI_METER_H__
#define __DPI_METER_H__

#include "dpi/dpi_packet.h"
#include "dpi/dpi_session.h"

typedef struct meter_info_ {
    char *name;
    uint32_t id;
    uint32_t log_id;
    uint8_t rate   :1,
            limit  :1, // Number of incidents is allowed every 'span' of seconds
            per_dst:1,
            per_src:1;
    uint8_t timeout;
    uint8_t log_timeout;
    uint8_t span; // If rate reaches 'limit' in 'span' of seconds, for example 100 in 10 seconds
    uint32_t upper_limit;
    uint32_t lower_limit;
} meter_info_t;

enum {
    DPI_METER_SYN_FLOOD = 0,
    DPI_METER_ICMP_FLOOD,
    DPI_METER_IP_SRC_SESSION,
    DPI_METER_TCP_NODATA,
    DPI_METER_MAX,
};

typedef struct dpi_meter_ {
    struct cds_lfht_node node;
    timer_entry_t ts_entry;

    io_ip_t peer_ip;
    uint8_t ep_mac[ETH_ALEN];
    uint8_t type;
#define DPI_METER_FLAG_ON   0x01
    uint8_t flags;
    uint32_t count, last_count, log_count;
    uint32_t start_tick, last_log;
    DPMsgThreatLog log;
} dpi_meter_t;

typedef enum dpi_meter_action_ {
    DPI_METER_ACTION_NONE = 0,
    DPI_METER_ACTION_CLEAR,
    DPI_METER_ACTION_PROXY,
} dpi_meter_action_t;

void dpi_meter_init(void);
int dpi_meter_packet_inc(uint8_t type, dpi_packet_t *p);
int dpi_meter_synflood_inc(dpi_packet_t *p);
int dpi_meter_session_inc(dpi_packet_t *p, dpi_session_t *s);
void dpi_meter_session_dec(dpi_session_t *s);
bool dpi_meter_session_rate(uint8_t type, dpi_session_t *s);

meter_info_t *dpi_get_meter_info(int type);

#endif
