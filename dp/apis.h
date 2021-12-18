#ifndef __DP_APIS_H__
#define __DP_APIS_H__

//
// Definitions between dpi and other modules.
//

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "jansson.h"
#include "urcu/list.h"
#include "utils/rcu_map.h"
#include "utils/bitmap.h"

#define MAX_THREAD_NAME_LEN 32
extern __thread int THREAD_ID;
extern __thread char THREAD_NAME[MAX_THREAD_NAME_LEN];

enum {
    CTRL_REQ_NONE = 0,
    CTRL_REQ_COUNT_SESSION,
    CTRL_REQ_LIST_SESSION,
    CTRL_REQ_CLEAR_SESSION,
    CTRL_REQ_LIST_METER,
    CTRL_REQ_DEL_MAC,
};

enum {
    CTRL_DLP_REQ_NONE = 0,
    CTRL_DLP_REQ_BLD,
    CTRL_DLP_REQ_DEL,
};

#define MAC_PREFIX "NeuV"
#define PROXYMESH_MAC_PREFIX "lkst"//0x6c6b7374
#define IFACE_NAME_LEN 32

typedef union io_ip_ {
    struct in6_addr ip6;
    uint32_t ip4;
} io_ip_t;

typedef struct io_counter_ {
    uint64_t pkt_id, err_pkts, unkn_pkts, ipv4_pkts, ipv6_pkts;
    uint64_t tcp_pkts, tcp_nosess_pkts, udp_pkts, icmp_pkts, other_pkts;
    uint64_t drop_pkts, total_asms, freed_asms;
    uint64_t total_frags, tmout_frags, freed_frags;

    uint64_t sess_id, tcp_sess, udp_sess, icmp_sess, ip_sess;
    uint32_t cur_sess, cur_tcp_sess, cur_udp_sess, cur_icmp_sess, cur_ip_sess;

    uint64_t parser_sess[DPI_PARSER_MAX], parser_pkts[DPI_PARSER_MAX];

    uint64_t drop_meters, proxy_meters;
    uint64_t cur_meters, cur_log_caches;
    uint32_t type1_rules, type2_rules, domains, domain_ips;
} io_counter_t;

#define STATS_SLOTS 60
#define STATS_INTERVAL 5 // in second
typedef struct io_metry_ {
    uint64_t session;
    uint64_t packet;
    uint64_t byte;
    uint32_t sess_ring[STATS_SLOTS];
    uint32_t pkt_ring[STATS_SLOTS];
    uint32_t byte_ring[STATS_SLOTS];
    uint32_t cur_session;
} io_metry_t;

typedef struct io_stats_ {
    uint32_t cur_slot;
    io_metry_t in, out;
    // io_metry_t app_in[DPI_PROTO_MAX];
    // io_metry_t app_out[DPI_PROTO_MAX];
} io_stats_t;

typedef struct io_app_ {
    struct cds_lfht_node node;
    uint16_t port;
    uint16_t proto;
    uint16_t server;
    uint16_t application;
#define SERVER_VER_SIZE 32
    char version[SERVER_VER_SIZE];
    bool listen;
    uint8_t ip_proto;
#define APP_SRC_CTRL  1
#define APP_SRC_DP    2
    uint8_t src;
} io_app_t;

typedef struct io_pip_ {
    uint32_t ip;
} io_pip_t;

typedef struct io_internal_pip_ {
    int count;
    io_pip_t list[0];
} io_internal_pip_t;

#define DLP_RULETYPE_INSIDE "inside"
#define DLP_RULETYPE_OUTSIDE "outside"
#define WAF_RULETYPE_INSIDE "wafinside"
#define WAF_RULETYPE_OUTSIDE "wafoutside"
// Broadcast, unicast and original mac both refer to this block.
struct io_mac_;
typedef struct io_ep_ {
    char iface[IFACE_NAME_LEN];
    struct io_mac_ *mac;    // Original MAC
    struct io_mac_ *ucmac;
    struct io_mac_ *bcmac;
    struct ether_addr pmac; // proxymesh's Original MAC
    io_internal_pip_t *pips; // proxymesh's parent IPs 

    uint32_t COPY_START;

    io_stats_t stats;

    rcu_map_t app_map;
    uint32_t app_updated;
    uint16_t app_ports;

    bool tap;
    uint8_t cassandra_svr: 1,
            kafka_svr:     1,
            couchbase_svr: 1,
            couchbase_clt: 1,
            zookeeper_svr: 1,
            zookeeper_clt: 1;
    void *policy_hdl;
    uint16_t policy_ver;

    rcu_map_t dlp_cfg_map;
    rcu_map_t waf_cfg_map;
    rcu_map_t dlp_rid_map;
    rcu_map_t waf_rid_map;
    void *dlp_detector;
    uint16_t dlp_detect_ver;
    bool dlp_inside;
} io_ep_t;

typedef struct io_mac_ {
    struct cds_lfht_node node;
    struct ether_addr mac;
    io_ep_t *ep;
    uint8_t broadcast:1,
            unicast:  1;
} io_mac_t;

typedef struct io_subnet4_ {
    uint32_t ip;
    uint32_t mask;
} io_subnet4_t;

typedef struct io_internal_subnet4_ {
    int count;
    io_subnet4_t list[0];
} io_internal_subnet4_t;

#define SPEC_INTERNAL_TUNNELIP "tunnelip"
#define SPEC_INTERNAL_SVCIP "svcip"
#define SPEC_INTERNAL_HOSTIP "hostip"
#define SPEC_INTERNAL_DEVIP "devip"
#define SPEC_INTERNAL_UWLIP "uwlip"
#define SPEC_INTERNAL_EXTIP "extip"

enum {
    DP_IPTYPE_NONE = 0,
    DP_IPTYPE_TUNNELIP,
    DP_IPTYPE_SVCIP,
    DP_IPTYPE_HOSTIP,
    DP_IPTYPE_DEVIP,
    DP_IPTYPE_UWLIP,
    DP_IPTYPE_EXTIP,
};

typedef struct io_spec_subnet4_ {
    uint32_t ip;
    uint32_t mask;
    uint8_t iptype;
} io_spec_subnet4_t;

typedef struct io_spec_internal_subnet4_ {
    int count;
    io_spec_subnet4_t list[0];
} io_spec_internal_subnet4_t;

typedef struct io_ctx_ {
    void *dp_ctx;
    uint32_t tick;
    uint32_t stats_slot;
    struct ether_addr ep_mac;
    bool large_frame;
    bool tap;
    bool tc;
    bool nfq;
} io_ctx_t;

typedef struct io_callback_ {
    int (*debug) (bool print_ts, const char *fmt, va_list args);
    int (*send_packet) (io_ctx_t *ctx, uint8_t *data, int len);
    int (*send_ctrl_json) (json_t *root);
    int (*send_ctrl_binary) (void *buf, int len);
    int (*threat_log) (DPMsgThreatLog *log);
    int (*traffic_log) (DPMsgSession *log);
    int (*connect_report) (DPMsgSession *log, int count_session, int count_violate);
} io_callback_t;

typedef struct dpi_config_ {
    bool enable_cksum;
    bool promisc;

    io_mac_t dummy_mac;
    io_ep_t dummy_ep;
} io_config_t;

#define DPI_INIT 0

typedef void (*dpi_stats_callback_fct)(io_stats_t *stats, io_stats_t *s);

// in
void dpi_setup(io_callback_t *cb, io_config_t *cfg);
void dpi_init(int reason);
int dpi_recv_packet(io_ctx_t *context, uint8_t *pkt, int len);
void dpi_timeout(uint32_t tick);

void dpi_handle_ctrl_req(int req, io_ctx_t *context);
void dpi_handle_dlp_ctrl_req(int req);
void dpi_get_device_counter(DPMsgDeviceCounter *c);
void dpi_count_session(DPMsgSessionCount *c);
void dpi_get_stats(io_stats_t *stats, dpi_stats_callback_fct cb);


#define GET_EP_FROM_MAC_MAP(buf)  (io_ep_t *)(buf + sizeof(io_mac_t) * 3)
typedef struct dpi_policy_app_rule_ {
    uint32_t rule_id;
    uint32_t app;
    uint8_t action;
} dpi_policy_app_rule_t;

#define MAX_FQDN_LEN DP_POLICY_FQDN_NAME_MAX_LEN
typedef struct dpi_policy_rule_ {
    uint32_t id;
    uint32_t sip;
    uint32_t sip_r;
    uint32_t dip;
    uint32_t dip_r;
    uint16_t dport;
    uint16_t dport_r;
    uint16_t proto;
    uint8_t action;
    bool ingress;
    char fqdn[MAX_FQDN_LEN];
    uint32_t num_apps;
    dpi_policy_app_rule_t *app_rules;
} dpi_policy_rule_t;

typedef struct dpi_policy_ {
    int num_macs;
    struct ether_addr *mac_list;
    int def_action;
    int apply_dir;
    int num_rules;
    dpi_policy_rule_t *rule_list;
} dpi_policy_t;

int dpi_policy_cfg(int cmd, dpi_policy_t *policy, int flag);
void dp_policy_destroy(void *policy_hdl);
void dpi_fqdn_entry_mark_delete(const char *name);
void dpi_fqdn_entry_delete_marked();

/*
 * -----------------------------------------------------
 * --- FQDN definition ---------------------------------
 * -----------------------------------------------------
 */
typedef struct fqdn_record_ {
    char name[MAX_FQDN_LEN];
    uint32_t code;
    uint32_t flag;
#define FQDN_RECORD_TO_DELETE      0x00000001
#define FQDN_RECORD_DELETED        0x00000002
#define FQDN_RECORD_WILDCARD       0x00000004
    uint32_t ip_cnt;
    uint32_t record_updated;//used for wildcard fqdn
    struct cds_list_head iplist;//FQDN->IP(s) mapping
} fqdn_record_t;

typedef struct fqdn_record_item_ {
    struct cds_list_head node;
    fqdn_record_t *r;
} fqdn_record_item_t;

typedef struct fqdn_name_entry_ {
    struct cds_lfht_node node;
    fqdn_record_t *r;
} fqdn_name_entry_t;

typedef struct fqdn_ipv4_entry_ {
    struct cds_lfht_node node;
    uint32_t ip;
    struct cds_list_head rlist;//IP->FQDN(s) mapping
} fqdn_ipv4_entry_t;

typedef struct fqdn_ipv4_item_ {
    struct cds_list_head node;
    uint32_t ip;
} fqdn_ipv4_item_t;

#define DPI_FQDN_DELETE_QLEN      32
#define DPI_FQDN_MAX_ENTRIES      DP_POLICY_FQDN_MAX_ENTRIES
typedef struct dpi_fqdn_hdl_ {
    rcu_map_t fqdn_name_map;
    rcu_map_t fqdn_ipv4_map;
    bitmap *bm;
    int code_cnt;
    int del_name_cnt;
    int del_ipv4_cnt;
    fqdn_name_entry_t *del_name_list[DPI_FQDN_DELETE_QLEN];
    fqdn_ipv4_entry_t *del_ipv4_list[DPI_FQDN_DELETE_QLEN];
    struct cds_list_head del_rlist;
} dpi_fqdn_hdl_t;

typedef struct fqdn_iter_ctx_ {
    dpi_fqdn_hdl_t *hdl;
    bool more;
} fqdn_iter_ctx_t;

uint32_t config_fqdn_ipv4_mapping(dpi_fqdn_hdl_t *hdl, char *name, uint32_t ip);

//dlp
#define MAX_DLP_RULE_NAME_LEN DP_DLP_RULE_NAME_MAX_LEN
#define MAX_DLP_RULE_PATTERN_LEN DP_DLP_RULE_PATTERN_MAX_LEN
#define MAX_DLPCFG_DELETE 256

typedef struct dpi_dlp_rule_pattern_ {
    char rule_pattern[MAX_DLP_RULE_PATTERN_LEN];
} dpi_dlp_rule_pattern_t;

typedef struct dpi_dlp_rule_entry_ {
    char rulename[MAX_DLP_RULE_NAME_LEN];
    uint32_t sigid;
    int num_dlp_rule_pats;
    dpi_dlp_rule_pattern_t *dlp_rule_pat_list;
} dpi_dlp_rule_entry_t;

typedef struct io_dlp_cfg_ {
    struct cds_lfht_node node;
    uint32_t sigid;
    uint8_t action;
    bool enable;
    struct cds_list_head sig_user_list;
} io_dlp_cfg_t;

typedef struct io_dlp_ruleid_ {
    struct cds_lfht_node node;
    uint32_t rid;
    bool enable;
} io_dlp_ruleid_t;

typedef struct dpi_dlpbld_ {
    int num_macs;
    struct ether_addr *mac_list;
    int num_del_macs;
    struct ether_addr *del_mac_list;
    int apply_dir;
    int num_dlp_rules;
    dpi_dlp_rule_entry_t *dlp_rule_list;
} dpi_dlpbld_t;

typedef struct dpi_dlpbld_mac_ {
    int num_old_macs;
    struct ether_addr *old_mac_list;
    int num_del_macs;
    struct ether_addr *del_mac_list;
    int num_add_macs;
    struct ether_addr *add_mac_list;
} dpi_dlpbld_mac_t;

int dpi_sig_bld(dpi_dlpbld_t *dlpsig, int flag);
int dpi_sig_bld_update_mac(dpi_dlpbld_mac_t *dlpbld_mac);
void dp_dlp_destroy(void *dlp_detector);

#define CTRL_REQ_TIMEOUT 4
#define CTRL_DLP_REQ_TIMEOUT 2
extern pthread_cond_t g_ctrl_req_cond;
extern pthread_mutex_t g_ctrl_req_lock;
extern int dp_data_wait_ctrl_req_thr(int req, int thr_id);
extern pthread_cond_t g_dlp_ctrl_req_cond;
extern pthread_mutex_t g_dlp_ctrl_req_lock;
extern int dp_dlp_wait_ctrl_req_thr(int req);

#endif
