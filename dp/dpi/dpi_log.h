#ifndef __DPI_LOG_H__
#define __DPI_LOG_H__

#include "dpi/dpi_module.h"
#include "dpi/dpi_meter.h"

enum {
    DPI_THRT_NONE = 0,
    DPI_THRT_TCP_FLOOD,
    DPI_THRT_ICMP_FLOOD,
    DPI_THRT_IP_SRC_SESSION,
    DPI_THRT_BAD_PACKET,
    DPI_THRT_IP_TEARDROP,
    DPI_THRT_TCP_SYN_DATA,
    DPI_THRT_TCP_SPLIT_HDSHK,
    DPI_THRT_TCP_NODATA,
    DPI_THRT_TCP_SMALL_WINDOW,
    DPI_THRT_TCP_SMALL_MSS,
    DPI_THRT_PING_DEATH,
    DPI_THRT_DNS_LOOP_PTR,
    DPI_THRT_SSH_VER_1,
    DPI_THRT_SSL_HEARTBLEED,
    DPI_THRT_SSL_CIPHER_OVF,
    DPI_THRT_SSL_VER_2OR3,
    DPI_THRT_SSL_TLS_1DOT0,
    DPI_THRT_HTTP_NEG_LEN,
    DPI_THRT_HTTP_SMUGGLING,
    DPI_THRT_HTTP_SLOWLORIS,
    DPI_THRT_DNS_OVERFLOW,
    DPI_THRT_MYSQL_ACCESS_DENY,
    DPI_THRT_DNS_ZONE_TRANSFER,
    DPI_THRT_ICMP_TUNNELING,
    DPI_THRT_DNS_TYPE_NULL,
    DPI_THRT_SQL_INJECTION,
    DPI_THRT_APACHE_STRUTS_RCE,
    DPI_THRT_K8S_EXTIP_MITM,
    DPI_THRT_MAX,
};

void dpi_log_init(void);
uint8_t dpi_threat_action(uint32_t idx);
bool dpi_threat_status(uint32_t idx);
void dpi_threat_trigger(uint32_t idx, dpi_packet_t *p, const char *format, ...);
void dpi_threat_trigger_flip(uint32_t idx, dpi_packet_t *p, const char *format, ...);
void dpi_threat_log_by_session(uint32_t idx, dpi_session_t *s, const char *format, ...);
void dpi_ddos_log(uint32_t idx, dpi_meter_t *m, const char *format, ...);

#define DPI_CONNECT_REPORT_INTERVAL       60
#define DPI_CONNECT_REPORT_INTERVAL_SHORT 15
int dpi_session_start_log(dpi_session_t *s, bool xff);
void dpi_session_mid_log(dpi_session_t *s, int log_violate, bool xff);

void dpi_session_log(dpi_session_t *sess, DPMsgSession *dps);
int dpi_session_log_xff(dpi_session_t *s, DPMsgSession *dps);
void dpi_policy_violate_log(dpi_packet_t *p, bool to_server,
                            dpi_policy_desc_t *desc);
void dpi_dlp_log_by_sig(dpi_packet_t *p, dpi_match_t *m, const char *format, ...);
void log_proxymesh_packet_detail(DPMsgThreatLog *log, dpi_packet_t *p, bool flip);

#endif
