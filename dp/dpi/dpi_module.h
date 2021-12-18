#ifndef __DPI_MODULE_H__
#define __DPI_MODULE_H__

#include <stdint.h>
#include <time.h>

#include "utils/rcu_map.h"
#include "utils/timer_wheel.h"

#include "apis.h"
#include "dpi/dpi_packet.h"
#include "dpi/dpi_session.h"
#include "dpi/dpi_debug.h"
#include "dpi/dpi_log.h"
#include "dpi/dpi_policy.h"

extern rcu_map_t g_ep_map;
extern io_internal_subnet4_t *g_internal_subnet4;
extern io_spec_internal_subnet4_t *g_specialip_subnet4;
extern uint8_t g_xff_enabled;
extern io_internal_subnet4_t *g_policy_addr;

typedef struct dpi_snap_ {
    uint32_t tick;
} dpi_snap_t;
    
extern io_callback_t *g_io_callback;
extern io_config_t *g_io_config;

// Thread data

typedef struct dpi_thread_data_ {
    dpi_packet_t packet;
    dpi_snap_t snap;
    io_counter_t counter;
	io_stats_t stats;

    rcu_map_t ip4frag_map;
    rcu_map_t ip6frag_map;
    rcu_map_t session4_map;
    rcu_map_t session4_proxymesh_map;
    rcu_map_t session6_map;
    rcu_map_t session6_proxymesh_map;
    rcu_map_t meter_map;
    rcu_map_t log_map;
    rcu_map_t unknown_ip_map;
	timer_wheel_t timer;

	io_internal_subnet4_t *subnet4;
	io_spec_internal_subnet4_t *specialipsubnet4;
	io_internal_subnet4_t *policyaddr;

	void *apache_struts_re_data;

    uint8_t dp_msg[DP_MSG_SIZE];
    uint32_t hs_detect_id;
    uint8_t xff_enabled;
} dpi_thread_data_t;

extern dpi_thread_data_t g_dpi_thread_data[];

#define th_packet   (g_dpi_thread_data[THREAD_ID].packet)
#define th_snap     (g_dpi_thread_data[THREAD_ID].snap)
#define th_counter  (g_dpi_thread_data[THREAD_ID].counter)
#define th_stats    (g_dpi_thread_data[THREAD_ID].stats)

#define th_ip4frag_map  (g_dpi_thread_data[THREAD_ID].ip4frag_map)
#define th_ip6frag_map  (g_dpi_thread_data[THREAD_ID].ip6frag_map)
#define th_session4_map (g_dpi_thread_data[THREAD_ID].session4_map)
#define th_session4_proxymesh_map (g_dpi_thread_data[THREAD_ID].session4_proxymesh_map)
#define th_session6_map (g_dpi_thread_data[THREAD_ID].session6_map)
#define th_session6_proxymesh_map (g_dpi_thread_data[THREAD_ID].session6_proxymesh_map)
#define th_meter_map    (g_dpi_thread_data[THREAD_ID].meter_map)
#define th_log_map      (g_dpi_thread_data[THREAD_ID].log_map)
#define th_unknown_ip_map      (g_dpi_thread_data[THREAD_ID].unknown_ip_map)
#define th_timer        (g_dpi_thread_data[THREAD_ID].timer)

#define th_internal_subnet4 (g_dpi_thread_data[THREAD_ID].subnet4)
#define th_specialip_subnet4 (g_dpi_thread_data[THREAD_ID].specialipsubnet4)
#define th_policy_addr (g_dpi_thread_data[THREAD_ID].policyaddr)

#define th_apache_struts_re_data (g_dpi_thread_data[THREAD_ID].apache_struts_re_data)

#define th_dp_msg   (g_dpi_thread_data[THREAD_ID].dp_msg)
#define th_hs_detect_id        (g_dpi_thread_data[THREAD_ID].hs_detect_id)
#define th_xff_enabled (g_dpi_thread_data[THREAD_ID].xff_enabled)

#endif
