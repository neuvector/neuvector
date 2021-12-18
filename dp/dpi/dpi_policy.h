#ifndef __DPI_POLICY_H__
#define __DPI_POLICY_H__

#include "dpi/dpi_packet.h"

typedef struct dpi_rule_key_ {
    uint32_t sip;
    uint32_t dip;
    uint16_t dport;
    uint16_t proto;
    uint32_t app;
} dpi_rule_key_t;

#define DP_RULE_STR "sip %x dip %x dport %d proto %d app %u "
#define DP_RULE_KEY(key) key->sip, key->dip, key->dport, key->proto, key->app

#define POLICY_ACTION_DEFAULT  DP_POLICY_ACTION_DENY

#define LEARNED_POLICY_START_ID      10000
#define DEFAULT_ICMP_PASS_POLICY_ID  0

typedef struct dpi_policy_desc_ {
    uint32_t id;
    uint8_t action;
    uint8_t flags;
#define POLICY_DESC_CHECK_VER      0x01
#define POLICY_DESC_INTERNAL       0x02
#define POLICY_DESC_EXTERNAL       0x04
#define POLICY_DESC_TUNNEL         0x08
#define POLICY_DESC_UNKNOWN_IP     0x10
#define POLICY_DESC_SVC_EXTIP      0x20
#define POLICY_DESC_HOSTIP         0x40
    uint16_t hdl_ver;
    uint32_t order;
} dpi_policy_desc_t;


typedef struct dpi_policy_hdl_ {
    uint16_t ref_cnt;
    uint16_t ver;
    rcu_map_t policy_map;
    rcu_map_t range_policy_map;
    int def_action;
    int apply_dir;
    uint32_t flag;
#define POLICY_HDL_FLAG_FQDN   0x01
} dpi_policy_hdl_t;

#define DPI_POLICY_HAS_FQDN(hdl) (hdl->flag & POLICY_HDL_FLAG_FQDN)

#define DPI_POLICY_LOG_VIOLATE(action) (action > DP_POLICY_ACTION_CHECK_APP)

#define DP_POLICY_DESC_STR "id %u action %d ver %u order %x "
#define DP_POLICY_DESC(desc) desc->id, desc->action, desc->hdl_ver, desc->order

enum {
    POLICY_RULE_DIR_EGRESS,
    POLICY_RULE_DIR_INGRESS,
    POLICY_RULE_DIR_NONE,
};

void dpi_policy_hdl_destroy(dpi_policy_hdl_t *hdl);
int dpi_policy_lookup(dpi_packet_t *p, dpi_policy_hdl_t *hdl, uint32_t app,
                      bool to_server, bool xff, dpi_policy_desc_t *desc, uint32_t xff_replace_dst_ip);
int dpi_policy_reeval(dpi_packet_t *p, bool to_server);
int dpi_policy_init();
int snooped_fqdn_ipv4_mapping(char *name, uint32_t *ip, int cnt);
void dpi_unknown_ip_init(void);

#endif
