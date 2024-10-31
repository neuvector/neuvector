#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "jansson.h"
#include "urcu.h"

#include "main.h"
#include "apis.h"
#include "debug.h"
#include "utils/helper.h"
#include "utils/rcu_map.h"
#include "utils/bits.h"
#include "dpi/sig/dpi_search.h"

extern int dp_data_add_port(const char *iface, bool jumboframe, int thr_id);
extern int dp_data_del_port(const char *iface, int thr_id);
extern int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);
extern int dp_data_del_tap(const char *netns, const char *iface, int thr_id);
extern int dp_data_add_nfq(const char *netns, const char *iface, int qnum, const char *ep_mac, bool jumboframe, int thr_id);
extern int dp_data_del_nfq(const char *netns, const char *iface, int thr_id);
extern int dp_read_ring_stats(dp_stats_t *s, int thr_id);
extern int dp_read_conn_stats(conn_stats_t *s, int thr_id);
extern int dp_data_add_port_pair(const char *vin_iface, const char *vex_iface,const char *ep_mac, bool quar, int thr_id);
extern int dp_data_del_port_pair(const char *vin_iface, const char *vex_iface, int thr_id);

extern rcu_map_t g_ep_map;
extern struct cds_list_head g_subnet4_list;
extern struct cds_list_head g_subnet6_list;
extern dpi_fqdn_hdl_t *g_fqdn_hdl;

pthread_cond_t g_ctrl_req_cond;
pthread_mutex_t g_ctrl_req_lock;
pthread_cond_t g_dlp_ctrl_req_cond;
pthread_mutex_t g_dlp_ctrl_req_lock;

static int g_ctrl_fd;
#define DP_SERVER_SOCK "/tmp/dp_listen.sock"
static struct sockaddr_un g_client_addr;

static int g_ctrl_notify_fd;
#define CTRL_NOTIFY_SOCK "/tmp/ctrl_listen.sock"
static struct sockaddr_un g_ctrl_notify_addr;

static uint8_t g_notify_msg[DP_MSG_SIZE];

static int make_notify_client(const char *filename)
{
    int sock;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    g_ctrl_notify_addr.sun_family = AF_UNIX;
    strlcpy(g_ctrl_notify_addr.sun_path, filename, sizeof(g_ctrl_notify_addr.sun_path));

    return sock;
}

// Send binary message actively to ctrl path
static int dp_ctrl_notify_ctrl(void *data, int len)
{
    socklen_t addr_len = sizeof(struct sockaddr_un);
    int sent = sendto(g_ctrl_notify_fd, data, len, 0,
                      (struct sockaddr *)&g_ctrl_notify_addr, addr_len);
    return sent;
}

static int make_named_socket(const char *filename)
{
    struct sockaddr_un name;
    int sock;
    size_t size;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    name.sun_family = AF_UNIX;
    strlcpy(name.sun_path, filename, sizeof(name.sun_path));

    size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path));

    if (bind(sock, (struct sockaddr *)&name, size) < 0) {
        return -1;
    }

    return sock;
}

// Send json message to client socket as response
int dp_ctrl_send_json(json_t *root)
{
    if (root == NULL) {
        DEBUG_ERROR(DBG_CTRL, "Fail to create json object.\n");
        return -1;
    }

    char *data = json_dumps(root, 0);
    if (data == NULL) {
        DEBUG_ERROR(DBG_CTRL, "Fail to dump json object.\n");
        json_decref(root);
        // 'root' steal all its children's reference. As it is released, return 0 so the caller
        // won't call free() again.
        return 0;
    }

    socklen_t addr_len = sizeof(struct sockaddr_un);
    //data is nul terminated according to json_dumps
    //so strlen(data) is safe here
    int sent = sendto(g_ctrl_fd, data, strlen(data), 0,
                      (struct sockaddr *)&g_client_addr, addr_len);
    DEBUG_CTRL("%s\n", data);

    free(data);
    json_decref(root);

    return sent;
}

// Send binary message to client socket as response
int dp_ctrl_send_binary(void *data, int len)
{
    socklen_t addr_len = sizeof(struct sockaddr_un);
    int sent = sendto(g_ctrl_fd, data, len, 0,
                      (struct sockaddr *)&g_client_addr, addr_len);

    return sent;
}

static int dp_ctrl_keep_alive(json_t *msg)
{
    uint32_t seq_num = json_integer_value(json_object_get(msg, "seq_num"));
    uint8_t buf[sizeof(DPMsgHdr) + sizeof(uint32_t)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_KEEP_ALIVE;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(uint32_t));
    hdr->More = 0;

    uint32_t *m = (uint32_t *)(buf + sizeof(DPMsgHdr));
    *m = htonl(seq_num);

    dp_ctrl_send_binary(buf, sizeof(buf));
    return 0;
}

static int dp_ctrl_add_tap_port(json_t *msg)
{
    const char *netns, *iface, *ep_mac;

    netns = json_string_value(json_object_get(msg, "netns"));
    iface = json_string_value(json_object_get(msg, "iface"));
    ep_mac = json_string_value(json_object_get(msg, "epmac"));
    DEBUG_CTRL("netns=%s iface=%s\n", netns, iface);

    return dp_data_add_tap(netns, iface, ep_mac, 0);
}

static int dp_ctrl_del_tap_port(json_t *msg)
{
    const char *netns, *iface;

    netns = json_string_value(json_object_get(msg, "netns"));
    iface = json_string_value(json_object_get(msg, "iface"));
    DEBUG_CTRL("netns=%s iface=%s\n", netns, iface);

    return dp_data_del_tap(netns, iface, 0);
}

static int dp_ctrl_add_nfq_port(json_t *msg)
{
    const char *netns, *iface, *ep_mac;
    json_t *jumboframe_obj;
    bool jumboframe = false;
    int qnum = 0;

    jumboframe_obj = json_object_get(msg, "jumboframe");
    if (jumboframe_obj != NULL) {
        jumboframe = json_boolean_value(jumboframe_obj);
    }

    netns = json_string_value(json_object_get(msg, "netns"));
    iface = json_string_value(json_object_get(msg, "iface"));
    qnum = json_integer_value(json_object_get(msg, "qnum"));

    ep_mac = json_string_value(json_object_get(msg, "epmac"));
    DEBUG_CTRL("add nfq netns=%s iface=%s, jumboframe=%d\n", netns, iface, jumboframe);

    return dp_data_add_nfq(netns, iface, qnum, ep_mac, jumboframe, 0);
}

static int dp_ctrl_del_nfq_port(json_t *msg)
{
    const char *netns, *iface;

    netns = json_string_value(json_object_get(msg, "netns"));
    iface = json_string_value(json_object_get(msg, "iface"));
    DEBUG_CTRL("del nfq netns=%s iface=%s\n", netns, iface);

    return dp_data_del_nfq(netns, iface, 0);
}

static int dp_ctrl_add_srvc_port(json_t *msg)
{
    const char *iface;
    json_t *jumboframe_obj;
    bool jumboframe = false;

    jumboframe_obj = json_object_get(msg, "jumboframe");
    if (jumboframe_obj != NULL) {
        jumboframe = json_boolean_value(jumboframe_obj);
    }

    iface = json_string_value(json_object_get(msg, "iface"));
    DEBUG_CTRL("iface=%s, jumboframe=%d\n", iface, jumboframe);

    return dp_data_add_port(iface, jumboframe, 0);
}

static int dp_ctrl_del_srvc_port(json_t *msg)
{
    const char *iface;

    iface = json_string_value(json_object_get(msg, "iface"));
    DEBUG_CTRL("iface=%s\n", iface);

    return dp_data_del_port(iface, 0);
}

static int dp_ctrl_add_port_pair(json_t *msg)
{
    const char *vex_iface, *vin_iface, *ep_mac;
    json_t *quar_obj;
    bool quar = false;

    quar_obj = json_object_get(msg, "quar");
    if (quar_obj != NULL) {
        quar = json_boolean_value(quar_obj);
    }

    vin_iface = json_string_value(json_object_get(msg, "vin_iface"));
    vex_iface = json_string_value(json_object_get(msg, "vex_iface"));
    ep_mac = json_string_value(json_object_get(msg, "epmac"));
    DEBUG_CTRL("Add vin %s: vex %s  epmac: %s quar: %d\n", vin_iface, vex_iface, ep_mac, quar);
    return dp_data_add_port_pair(vin_iface, vex_iface, ep_mac, quar, 0);
}

static int dp_ctrl_del_port_pair(json_t *msg)
{
    const char *vex_iface, *vin_iface;

    vin_iface = json_string_value(json_object_get(msg, "vin_iface"));
    vex_iface = json_string_value(json_object_get(msg, "vex_iface"));
    DEBUG_CTRL("Del vin %s: vex %s\n", vin_iface, vex_iface);
    return dp_data_del_port_pair(vin_iface, vex_iface, 0);
}

static uint32_t ep_app_hash(const void *key)
{
    const io_app_t *app = key;
    return app->port ^ app->ip_proto;
}

static int ep_app_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_app_t *app = STRUCT_OF(ht_node, io_app_t, node);
    const io_app_t *k = key;
    return app->port == k->port && app->ip_proto == k->ip_proto;
}

static void dp_pips_destroy(io_ep_t *ep)
{
    if (ep->pips) {
        free(ep->pips);
    }
}

static void ep_app_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->app_map, node) {
       io_app_t *app = STRUCT_OF(node, io_app_t, node);
       rcu_map_del(&ep->app_map, app);
       free(app);
    }
    rcu_map_destroy(&ep->app_map);
}

static uint32_t ep_dlp_cfg_hash(const void *key)
{
    const io_dlp_cfg_t *dlpcfg = key;
    return sdbm_hash((uint8_t *)&dlpcfg->sigid, sizeof(uint32_t));
}

static int ep_dlp_cfg_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_dlp_cfg_t *dlpcfg = STRUCT_OF(ht_node, io_dlp_cfg_t, node);
    const io_dlp_cfg_t *k = key;
    return dlpcfg->sigid == k->sigid;
}

static void ep_dlp_cfg_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->dlp_cfg_map, node) {
        io_dlp_cfg_t *dlpcfg = STRUCT_OF(node, io_dlp_cfg_t, node);
        rcu_map_del(&ep->dlp_cfg_map, dlpcfg);

        if (dlpcfg->sig_user_list.prev == NULL && dlpcfg->sig_user_list.next == NULL) {
            CDS_INIT_LIST_HEAD(&dlpcfg->sig_user_list);
        }
        
        dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
        cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &dlpcfg->sig_user_list, node) {
            cds_list_del((struct cds_list_head *)sig_user_itr);
            if (sig_user_itr->sig_user) {
                free(sig_user_itr->sig_user);
            }
            free(sig_user_itr);
        }
       free(dlpcfg);
    }
    rcu_map_destroy(&ep->dlp_cfg_map);
}

static void ep_waf_cfg_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->waf_cfg_map, node) {
        io_dlp_cfg_t *wafcfg = STRUCT_OF(node, io_dlp_cfg_t, node);
        rcu_map_del(&ep->waf_cfg_map, wafcfg);

        if (wafcfg->sig_user_list.prev == NULL && wafcfg->sig_user_list.next == NULL) {
            CDS_INIT_LIST_HEAD(&wafcfg->sig_user_list);
        }
        
        dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
        cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &wafcfg->sig_user_list, node) {
            cds_list_del((struct cds_list_head *)sig_user_itr);
            if (sig_user_itr->sig_user) {
                free(sig_user_itr->sig_user);
            }
            free(sig_user_itr);
        }
       free(wafcfg);
    }
    rcu_map_destroy(&ep->waf_cfg_map);
}

static uint32_t ep_dlp_ruleid_hash(const void *key)
{
    const io_dlp_ruleid_t *dlprid = key;
    return sdbm_hash((uint8_t *)&dlprid->rid, sizeof(uint32_t));
}

static int ep_dlp_ruleid_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_dlp_ruleid_t *dlprid = STRUCT_OF(ht_node, io_dlp_ruleid_t, node);
    const io_dlp_ruleid_t *k = key;
    return dlprid->rid == k->rid;
}

static void ep_dlp_rid_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->dlp_rid_map, node) {
       io_dlp_ruleid_t *dlprid = STRUCT_OF(node, io_dlp_ruleid_t, node);
       rcu_map_del(&ep->dlp_rid_map, dlprid);
       free(dlprid);
    }
    rcu_map_destroy(&ep->dlp_rid_map);
}

static void ep_waf_rid_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->waf_rid_map, node) {
       io_dlp_ruleid_t *wafrid = STRUCT_OF(node, io_dlp_ruleid_t, node);
       rcu_map_del(&ep->waf_rid_map, wafrid);
       free(wafrid);
    }
    rcu_map_destroy(&ep->waf_rid_map);
}

static void ep_destroy(io_ep_t *ep)
{
    ep_app_destroy(ep);
    dp_policy_destroy(ep->policy_hdl);
    ep_dlp_cfg_destroy(ep);
    ep_waf_cfg_destroy(ep);
    ep_dlp_rid_destroy(ep);
    ep_waf_rid_destroy(ep);
    dp_dlp_destroy(ep->dlp_detector);
    dp_pips_destroy(ep);
}

static int dp_ctrl_add_mac(json_t *msg)
{
    void *buf;
    io_ep_t *ep;
    io_mac_t *mac, *ucmac, *bcmac;
    struct ether_addr oldmac;
    const char *mac_str, *ucmac_str, *bcmac_str, *oldmac_str, *pmac_str;
    size_t ucl, bcl, oml, pml;
    const char *iface;
    int i, count=0;
    json_t *obj, *nw_obj;
    io_internal_pip_t *pips = NULL;

    iface = json_string_value(json_object_get(msg, "iface"));
    mac_str = json_string_value(json_object_get(msg, "mac"));
    ucmac_str = json_string_value(json_object_get(msg, "ucmac"));
    ucl = json_string_length(json_object_get(msg, "ucmac"));

    bcmac_str = json_string_value(json_object_get(msg, "bcmac"));
    bcl = json_string_length(json_object_get(msg, "bcmac"));

    oldmac_str = json_string_value(json_object_get(msg, "oldmac"));
    oml = json_string_length(json_object_get(msg, "oldmac"));

    pmac_str = json_string_value(json_object_get(msg, "pmac"));
    pml = json_string_length(json_object_get(msg, "pmac"));

    obj = json_object_get(msg, "pips");
    if (obj) {
        count = json_array_size(obj);
        pips = calloc(sizeof(io_internal_pip_t) + count * sizeof(io_pip_t), 1);
        if (!pips) {
            DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
            return -1;
        }
        pips->count = count;
        for (i = 0; i < count; i++) {
            nw_obj = json_array_get(obj, i);
            pips->list[i].ip = inet_addr(json_string_value(json_object_get(nw_obj, "ip")));
        }
    }

    DEBUG_CTRL("mac=%s ucmac=%s oldmac=%s pmac=%s\n", mac_str, ucmac_str, oldmac_str, pmac_str);

    buf = calloc(1, sizeof(io_mac_t) * 3 + sizeof(*ep));
    if (buf == NULL) {
        free(pips);
        return -1;
    }
    // buf ->
    //   io_mac_t:     mac
    //   io_mac_t:     ucmac
    //   io_mac_t:     bcmac
    //   io_ep_t:      ep
    mac = (io_mac_t *)buf;
    ucmac = (io_mac_t *)(buf + sizeof(io_mac_t));
    bcmac = (io_mac_t *)(buf + sizeof(io_mac_t) * 2);
    ep = (io_ep_t *)(buf + sizeof(io_mac_t) * 3);
    ep->mac = mac;
    ep->ucmac = ucmac;
    ep->bcmac = bcmac;
    ep->cassandra_svr = false;
    ep->kafka_svr = false;
    ep->couchbase_svr = false;
    ep->zookeeper_svr = false;

    ether_aton_r(mac_str, &mac->mac);
    mac->ep = ep;
    if (ucl > 0) {
        ether_aton_r(ucmac_str, &ucmac->mac);
        ucmac->unicast = 1;
        ucmac->ep = ep;
    }
    if (bcl > 0) {
        ether_aton_r(bcmac_str, &bcmac->mac);
        bcmac->broadcast = 1;
        bcmac->ep = ep;
    }
    if (oml > 0) {
        ether_aton_r(oldmac_str, &oldmac);
    } else {
        oldmac = mac->mac;
    }
    //for proxymesh ep, we need original ep's MAC to get policy handle
    if (pml > 0) {
        ether_aton_r(pmac_str, &ep->pmac);
    }
    //proxymesh ep, we need original ep's IPs to do xff policy match
    //for 5-tuple whose src and dst IP is 127.0.0.x
    ep->pips = pips;

    strlcpy(ep->iface, iface, sizeof(ep->iface));

    // Add to map
    // Although MAC of a container port doesn't change, UCMAC and BCMAC can be added (tap->inline)
    // or changed (switching between tap and inline back and forth)
    void *old_buf;

    rcu_read_lock();
    old_buf = rcu_map_lookup(&g_ep_map, &oldmac);
    if (old_buf != NULL) {
        /* keep the old policy hdl if any */
        io_ep_t *old_ep;
        old_ep = (io_ep_t *)(old_buf + sizeof(io_mac_t) * 3);

        memcpy(&ep->COPY_START, &old_ep->COPY_START, sizeof(io_ep_t) - offsetof(io_ep_t, COPY_START));
        DEBUG_CTRL("copy existing ep, policy hdl %p.\n", old_ep->policy_hdl);

        // Remove the old unicast/broadcast mac entry
        rcu_map_del(&g_ep_map, old_buf);

        io_mac_t *old_ucmac = old_buf + sizeof(io_mac_t);
        if (!mac_zero(old_ucmac->mac.ether_addr_octet)) {
            rcu_map_del(&g_ep_map, old_ucmac);
        }
        io_mac_t *old_bcmac = old_buf + sizeof(io_mac_t) * 2;
        if (!mac_zero(old_bcmac->mac.ether_addr_octet)) {
            rcu_map_del(&g_ep_map, old_bcmac);
        }

        // Add the new mac entry
        rcu_map_add(&g_ep_map, mac, &mac->mac);
        if (!mac_zero(ucmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, ucmac, &ucmac->mac);
        }
        if (!mac_zero(bcmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, bcmac, &bcmac->mac);
        }

        rcu_read_unlock();
        synchronize_rcu();

        // Pointers are copied to the new ep. Reset pointers in the old ep to prevent data from being destroyed.
        old_ep->policy_hdl = NULL;
        rcu_map_init(&old_ep->app_map, 8, offsetof(io_app_t, node), ep_app_match, ep_app_hash);
        //dlp
        old_ep->dlp_detector = NULL;
        rcu_map_init(&old_ep->dlp_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&old_ep->waf_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&old_ep->dlp_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        rcu_map_init(&old_ep->waf_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        ep_destroy(old_ep);

        free(old_buf);

        DEBUG_CTRL("replace %s to ep map.\n", mac_str);
    } else {
        rcu_map_init(&ep->app_map, 8, offsetof(io_app_t, node), ep_app_match, ep_app_hash);
        rcu_map_init(&ep->dlp_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&ep->waf_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&ep->dlp_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        rcu_map_init(&ep->waf_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        ep->tap = true;

        rcu_map_add(&g_ep_map, mac, &mac->mac);
        if (!mac_zero(ucmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, ucmac, &ucmac->mac);
        }
        if (!mac_zero(bcmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, bcmac, &bcmac->mac);
        }

        rcu_read_unlock();
        DEBUG_CTRL("add %s to ep map.\n", mac_str);
    }

    return 0;
}

struct ether_addr *g_mac_addr_to_del = NULL;
static int dp_dpi_del_mac(struct ether_addr *mac_addr)
{
    g_mac_addr_to_del = mac_addr;

    int thr_id;
    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_data_wait_ctrl_req_thr(CTRL_REQ_DEL_MAC, thr_id);
    }

    g_mac_addr_to_del = NULL;
    return 0;
}

static int dp_ctrl_del_mac(json_t *msg)
{
    struct ether_addr mac_addr;
    const char *mac_str;

    mac_str = json_string_value(json_object_get(msg, "mac"));
    ether_aton_r(mac_str, &mac_addr);

    DEBUG_CTRL("mac=%s\n", mac_str);

    rcu_read_lock();
    void *old_buf = rcu_map_lookup(&g_ep_map, &mac_addr);
    if (old_buf == NULL) {
        rcu_read_unlock();
        DEBUG_CTRL("mac %s not found in ep map.\n", mac_str);
        return -1;
    } else {
        rcu_map_del(&g_ep_map, old_buf);

        io_mac_t *old_ucmac = old_buf + sizeof(io_mac_t);
        rcu_map_del(&g_ep_map, old_ucmac);

        io_mac_t *old_bcmac = old_buf + sizeof(io_mac_t) * 2;
        rcu_map_del(&g_ep_map, old_bcmac);

        rcu_read_unlock();
        synchronize_rcu();

        io_ep_t *ep = (io_ep_t *)(old_buf + sizeof(io_mac_t) * 3);
        ep_destroy(ep);

        free(old_buf);

        DEBUG_CTRL("remove %s from ep map.\n", mac_str);
        dp_dpi_del_mac(&mac_addr);
    }

    return 0;
}

static int dp_ctrl_cfg_nbe(json_t *msg)
{
    json_t *obj, *nbe_obj;
    bool nbe = false;
    int len, i;

    obj = json_object_get(msg, "macs");
    nbe_obj = json_object_get(msg, "nbe");
    if (nbe_obj != NULL) {
        nbe = json_boolean_value(nbe_obj);
    }

    len = json_array_size(obj);
    if (len == 0) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in mac cfg!!\n");
        return -1;
    }

    rcu_read_lock();
    for (i = 0; i < len; i ++) {
        struct ether_addr mac_addr;
        const char *mac_str = json_string_value(json_array_get(obj, i));
        ether_aton_r(mac_str, &mac_addr);

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, &mac_addr);
        if (mac == NULL) {
            DEBUG_ERROR(DBG_CTRL, "mac %s not found in ep map.\n", mac_str);
            continue;
        }

        io_ep_t *ep = mac->ep;
        if (nbe_obj != NULL) {
            ep->nbe = nbe;
        }
        DEBUG_CTRL("mac=%s, ep->nbe=%d\n", mac_str, nbe);
    }
    rcu_read_unlock();
    return 0;
}

static int dp_ctrl_cfg_mac(json_t *msg)
{
    json_t *obj, *tap_obj, *app_obj;
    bool tap = false;
    int len, i;
#define MAX_APP_DELETE 64
    struct cds_lfht_node *app_node_list[MAX_APP_DELETE];
    int cnt = 0;

    obj = json_object_get(msg, "macs");
    tap_obj = json_object_get(msg, "tap");
    if (tap_obj != NULL) {
        tap = json_boolean_value(tap_obj);
    }
    app_obj = json_object_get(msg, "apps");

    len = json_array_size(obj);
    if (len == 0) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in mac cfg!!\n");
        return -1;
    }

    rcu_read_lock();
    for (i = 0; i < len; i ++) {
        struct ether_addr mac_addr;
        const char *mac_str = json_string_value(json_array_get(obj, i));
        ether_aton_r(mac_str, &mac_addr);

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, &mac_addr);
        if (mac == NULL) {
            DEBUG_ERROR(DBG_CTRL, "mac %s not found in ep map.\n", mac_str);
            continue;
        }

        io_ep_t *ep = mac->ep;
        if (tap_obj != NULL) {
            ep->tap = tap;
        }

        // Listening ports and apps
        if (app_obj != NULL) {
            int j;
            struct cds_lfht_node *app_node;
            RCU_MAP_FOR_EACH(&ep->app_map, app_node) {
                io_app_t *app = STRUCT_OF(app_node, io_app_t, node);
                if (app->src == APP_SRC_CTRL) {
                    app->src = 0;
                }
            }
            for (j = 0; j < json_array_size(app_obj); j++) {
                json_t *l = json_array_get(app_obj, j);
                uint16_t port = json_integer_value(json_object_get(l, "port"));
                uint8_t ip_proto = json_integer_value(json_object_get(l, "ip_proto"));
                uint16_t app_id = json_integer_value(json_object_get(l, "app"));
                uint16_t server_id = json_integer_value(json_object_get(l, "server"));

                io_app_t key;
                key.port = port;
                key.ip_proto = ip_proto;
                io_app_t *app = rcu_map_lookup(&ep->app_map, &key);
                if (app == NULL) {
                    if ((app = calloc(1, sizeof(*app))) != NULL) {
                        ep->app_ports ++;

                        app->port = port;
                        app->ip_proto = ip_proto;
                        app->application = app_id;
                        app->server = server_id;
                        app->listen = true;
                        app->src = APP_SRC_CTRL;
                        rcu_map_add(&ep->app_map, app, app);
                    }
                } else if (app->src == 0) {
                    app->src = APP_SRC_CTRL;
                }
            }
            do {
                RCU_MAP_FOR_EACH(&ep->app_map, app_node) {
                    io_app_t *app = STRUCT_OF(app_node, io_app_t, node);
                    if (app->src == 0 && cnt < MAX_APP_DELETE) {
                        DEBUG_CTRL("remove port %d app %d from ep %s app map.\n",
                               app->port, app->application, mac_str);
                        rcu_map_del(&ep->app_map, app_node);
                        app_node_list[cnt] = app_node;
                        cnt++;
                    }
                }
            } while (0);
        }
    }
    rcu_read_unlock();
    if (cnt > 0) {
        synchronize_rcu();
        for (i = 0; i < cnt; i++) {
            free(app_node_list[i]);
        }
    }
    return 0;
}

#define APPS_PER_MSG ((DP_MSG_SIZE - sizeof(DPMsgHdr) - sizeof(DPMsgAppHdr)) / sizeof(DPMsgApp))

static void dp_ctrl_update_app(bool refresh)
{
    struct cds_lfht_node *node, *app_node;

    // Iterate through all MAC
    RCU_MAP_FOR_EACH(&g_ep_map, node) {
        io_mac_t *mac = STRUCT_OF(node, io_mac_t, node);
        if (mac->broadcast || mac->unicast) continue;

        io_ep_t *ep = mac->ep;
        if (ep->app_ports == 0) continue;

        if (refresh) {
            uatomic_set(&ep->app_updated, 0);
        } else if (uatomic_cmpxchg(&ep->app_updated, 1, 0) == 0) {
            continue;
        }

        int ports = 0;

        DPMsgHdr *hdr = (DPMsgHdr *)g_notify_msg;
        DPMsgAppHdr *ah = (DPMsgAppHdr *)(g_notify_msg + sizeof(*hdr));
        DPMsgApp *apps = (DPMsgApp *)(g_notify_msg + sizeof(*hdr) + sizeof(*ah));

        hdr->Kind = DP_KIND_APP_UPDATE;
        memcpy(&ah->MAC, &mac->mac, sizeof(ah->MAC));

        // Iterate through all apps
        RCU_MAP_FOR_EACH(&ep->app_map, app_node) {
            io_app_t *app = STRUCT_OF(app_node, io_app_t, node);

            apps->Port = htons(app->port);
            apps->IPProto = app->ip_proto;
            apps->Proto = htons(app->proto);
            apps->Server = htons(app->server);
            apps->Application = htons(app->application);

            apps ++;
            ports ++;
            if (ports == APPS_PER_MSG) {
                break;
            }
        }

        uint16_t len = sizeof(*hdr) + sizeof(*ah) + sizeof(DPMsgApp) * ports;
        hdr->Length = htons(len);
        ah->Ports = htons(ports);

        if (ep->app_ports != ports) {
            DEBUG_CTRL("Not all ports are sent. ports=%u sent=%u\n", ep->app_ports, ports);
        }

        DEBUG_CTRL("mac="DBG_MAC_FORMAT" ports=%d\n", DBG_MAC_TUPLE(mac->mac), ports);

        dp_ctrl_notify_ctrl(g_notify_msg, len);
    }
}

static int dp_ctrl_refresh_app(json_t *msg)
{
    dp_ctrl_update_app(true);
    return 0;
}

typedef struct ctrl_stats_ {
    uint64_t session;
    uint64_t cur_session;
    uint64_t packet;
    uint64_t byte;
    uint64_t sess1;
    uint64_t pkt1;
    uint64_t byte1;
    uint64_t sess12;
    uint64_t pkt12;
    uint64_t byte12;
    uint64_t sess60;
    uint64_t pkt60;
    uint64_t byte60;
} ctrl_stats_t;

static void collect_stats(ctrl_stats_t *stats, io_metry_t *a, uint32_t cur, uint32_t last)
{
    register uint32_t s, n;
    register uint64_t sess, pkt, byte;

    stats->session = a->session;
    stats->cur_session = a->cur_session;
    stats->packet = a->packet;
    stats->byte = a->byte;

    // 5s, last slot
    if (cur > 0 && last + 1 >= cur) {
        s = (cur - 1) % STATS_SLOTS;
        stats->sess1 = a->sess_ring[s];
        stats->pkt1 = a->pkt_ring[s];
        stats->byte1 = a->byte_ring[s];
    }

    // 12s
    if (last + 12 >= cur) {
        uint32_t from = (cur >= 12) ? cur - 12 : 0;
        sess = pkt = byte = 0;
        for (n = from; n < last; n ++) {
            s = n % STATS_SLOTS;
            sess += a->sess_ring[s];
            pkt += a->pkt_ring[s];
            byte += a->byte_ring[s];
        }
        stats->sess12 = sess;
        stats->pkt12 = pkt;
        stats->byte12 = byte;
    }

    // 60s
    if (last + 59 >= cur) {
        uint32_t from = (cur >= 59) ? cur - 59 : 0;
        sess = pkt = byte = 0;
        for (n = from; n < last; n ++) {
            s = n % STATS_SLOTS;
            sess += a->sess_ring[s];
            pkt += a->pkt_ring[s];
            byte += a->byte_ring[s];
        }
        stats->sess60 = sess;
        stats->pkt60 = pkt;
        stats->byte60 = byte;
    }
}

static int dp_ctrl_stats_macs(json_t *msg)
{
    uint8_t buf[sizeof(DPMsgHdr) + sizeof(DPMsgStats)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_MAC_STATS;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(DPMsgStats));
    hdr->More = 0;

    DPMsgStats *m = (DPMsgStats *)(buf + sizeof(DPMsgHdr));
    memset(m, 0, sizeof(*m));

    rcu_read_lock();

    json_t *macs = json_object_get(msg, "macs");

    int i;
    for (i = 0; i < json_array_size(macs); i ++) {
        const char *mac_str = json_string_value(json_array_get(macs, i));
        struct ether_addr mac_addr;
        ether_aton_r(mac_str, &mac_addr);

        DEBUG_CTRL("mac=%s\n", mac_str);

        io_mac_t *mac = rcu_map_lookup(&g_ep_map, &mac_addr);
        if (mac == NULL) {
            DEBUG_ERROR(DBG_CTRL, "mac %s not found in ep map.\n", mac_str);
            continue;
        }

        io_stats_t *s = &mac->ep->stats;
        ctrl_stats_t in, out;

        memset(&in, 0, sizeof(in));
        memset(&out, 0, sizeof(out));

        collect_stats(&in, &s->in, g_stats_slot, s->cur_slot);
        collect_stats(&out, &s->out, g_stats_slot, s->cur_slot);

        m->Interval = STATS_INTERVAL;

        m->SessionIn += in.session;
        m->SessionOut += out.session;
        m->SessionCurIn += in.cur_session;
        m->SessionCurOut += out.cur_session;
        m->PacketIn += in.packet;
        m->PacketOut += out.packet;
        m->ByteIn += in.byte;
        m->ByteOut += out.byte;

        m->SessionIn1 += in.sess1;
        m->SessionOut1 += out.sess1;
        m->PacketIn1 += in.pkt1;
        m->PacketOut1 += out.pkt1;
        m->ByteIn1 += in.byte1;
        m->ByteOut1 += out.byte1;

        m->SessionIn12 += in.sess12;
        m->SessionOut12 += out.sess12;
        m->PacketIn12 += in.pkt12;
        m->PacketOut12 += out.pkt12;
        m->ByteIn12 += in.byte12;
        m->ByteOut12 += out.byte12;

        m->SessionIn60 += in.sess60;
        m->SessionOut60 += out.sess60;
        m->PacketIn60 += in.pkt60;
        m->PacketOut60 += out.pkt60;
        m->ByteIn60 += in.byte60;
        m->ByteOut60 += out.byte60;
    }

    rcu_read_unlock();

    m->SessionIn = htonl(m->SessionIn);
    m->SessionOut = htonl(m->SessionOut);
    m->SessionCurIn = htonl(m->SessionCurIn);
    m->SessionCurOut = htonl(m->SessionCurOut);
    m->PacketIn = htonll(m->PacketIn);
    m->PacketOut = htonll(m->PacketOut);
    m->ByteIn = htonll(m->ByteIn);
    m->ByteOut = htonll(m->ByteOut);

    m->SessionIn1 = htonl(m->SessionIn1);
    m->SessionOut1 = htonl(m->SessionOut1);
    m->PacketIn1 = htonll(m->PacketIn1);
    m->PacketOut1 = htonll(m->PacketOut1);
    m->ByteIn1 = htonll(m->ByteIn1);
    m->ByteOut1 = htonll(m->ByteOut1);

    m->SessionIn12 = htonl(m->SessionIn12);
    m->SessionOut12 = htonl(m->SessionOut12);
    m->PacketIn12 = htonll(m->PacketIn12);
    m->PacketOut12 = htonll(m->PacketOut12);
    m->ByteIn12 = htonll(m->ByteIn12);
    m->ByteOut12 = htonll(m->ByteOut12);

    m->SessionIn60 = htonl(m->SessionIn60);
    m->SessionOut60 = htonl(m->SessionOut60);
    m->PacketIn60 = htonll(m->PacketIn60);
    m->PacketOut60 = htonll(m->PacketOut60);
    m->ByteIn60 = htonll(m->ByteIn60);
    m->ByteOut60 = htonll(m->ByteOut60);

    dp_ctrl_send_binary(buf, sizeof(buf));

    return 0;
}

static void dpi_stats_callback(io_stats_t *stats, io_stats_t *s)
{
    stats->in.session += s->in.session;
    stats->in.cur_session += s->in.cur_session;
    stats->in.packet += s->in.packet;
    stats->in.byte += s->in.byte;
    stats->out.session += s->out.session;
    stats->out.cur_session += s->out.cur_session;
    stats->out.packet += s->out.packet;
    stats->out.byte += s->out.byte;

    uint32_t start = (g_stats_slot < STATS_SLOTS) ? 0 : g_stats_slot - STATS_SLOTS;
    uint32_t end = min(g_stats_slot, s->cur_slot + 1);
    int i, r;

    for (i = 0; start < end; i ++, start ++) {
        r = start % STATS_SLOTS;
        stats->in.sess_ring[i] += s->in.sess_ring[r];
        stats->in.pkt_ring[i] += s->in.pkt_ring[r];
        stats->in.byte_ring[i] += s->in.byte_ring[r];
        stats->out.sess_ring[i] += s->out.sess_ring[r];
        stats->out.pkt_ring[i] += s->out.pkt_ring[r];
        stats->out.byte_ring[i] += s->out.byte_ring[r];
    }
}

static int dp_ctrl_stats_device(json_t *msg)
{
    io_stats_t stats;

    memset(&stats, 0, sizeof(stats));

    // stats of different threads are aligned to 'stats' from 0 to STATS_SLOTS - 1
    dpi_get_stats(&stats, dpi_stats_callback);

    ctrl_stats_t in, out;
    int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.session = stats.in.session;
    in.cur_session = stats.in.cur_session;
    in.packet = stats.in.packet;
    in.byte = stats.in.byte;
    out.session = stats.out.session;
    out.cur_session = stats.out.cur_session;
    out.packet = stats.out.packet;
    out.byte = stats.out.byte;
    in.sess1 = stats.in.sess_ring[STATS_SLOTS - 1];
    in.pkt1 = stats.in.pkt_ring[STATS_SLOTS - 1];
    in.byte1 = stats.in.byte_ring[STATS_SLOTS - 1];
    out.sess1 = stats.out.sess_ring[STATS_SLOTS - 1];
    out.pkt1 = stats.out.pkt_ring[STATS_SLOTS - 1];
    out.byte1 = stats.out.byte_ring[STATS_SLOTS - 1];
    for (i = STATS_SLOTS - 12; i < STATS_SLOTS; i ++) {
        in.sess12 += stats.in.sess_ring[i];
        in.pkt12 += stats.in.pkt_ring[i];
        in.byte12 += stats.in.byte_ring[i];
        out.sess12 += stats.out.sess_ring[i];
        out.pkt12 += stats.out.pkt_ring[i];
        out.byte12 += stats.out.byte_ring[i];
    }
    for (i = STATS_SLOTS - 60; i < STATS_SLOTS; i ++) {
        in.sess60 += stats.in.sess_ring[i];
        in.pkt60 += stats.in.pkt_ring[i];
        in.byte60 += stats.in.byte_ring[i];
        out.sess60 += stats.out.sess_ring[i];
        out.pkt60 += stats.out.pkt_ring[i];
        out.byte60 += stats.out.byte_ring[i];
    }

    uint8_t buf[sizeof(DPMsgHdr) + sizeof(DPMsgStats)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_DEVICE_STATS;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(DPMsgStats));
    hdr->More = 0;

    DPMsgStats *m = (DPMsgStats *)(buf + sizeof(DPMsgHdr));
    memset(m, 0, sizeof(*m));

    m->Interval = htonl(STATS_INTERVAL);

    m->SessionIn = htonl(in.session);
    m->SessionOut = htonl(out.session);
    m->SessionCurIn = htonl(in.cur_session);
    m->SessionCurOut = htonl(out.cur_session);
    m->PacketIn = htonll(in.packet);
    m->PacketOut = htonll(out.packet);
    m->ByteIn = htonll(in.byte);
    m->ByteOut = htonll(out.byte);

    m->SessionIn1 = htonl(in.sess1);
    m->SessionOut1 = htonl(out.sess1);
    m->PacketIn1 = htonll(in.pkt1);
    m->PacketOut1 = htonll(out.pkt1);
    m->ByteIn1 = htonll(in.byte1);
    m->ByteOut1 = htonll(out.byte1);

    m->SessionIn12 = htonl(in.sess12);
    m->SessionOut12 = htonl(out.sess12);
    m->PacketIn12 = htonll(in.pkt12);
    m->PacketOut12 = htonll(out.pkt12);
    m->ByteIn12 = htonll(in.byte12);
    m->ByteOut12 = htonll(out.byte12);

    m->SessionIn60 = htonl(in.sess60);
    m->SessionOut60 = htonl(out.sess60);
    m->PacketIn60 = htonll(in.pkt60);
    m->PacketOut60 = htonll(out.pkt60);
    m->ByteIn60 = htonll(in.byte60);
    m->ByteOut60 = htonll(out.byte60);

    dp_ctrl_send_binary(buf, sizeof(buf));

    return 0;
}

static int dp_ctrl_counter_device(json_t *msg)
{
    uint8_t buf[sizeof(DPMsgHdr) + sizeof(DPMsgDeviceCounter)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_DEVICE_COUNTER;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(DPMsgDeviceCounter));
    hdr->More = 0;

    DPMsgDeviceCounter *c = (DPMsgDeviceCounter *)(buf + sizeof(DPMsgHdr));
    memset(c, 0, sizeof(*c));
    dpi_get_device_counter(c);

    c->ErrorPackets = htonll(c->ErrorPackets);
    c->NoWorkloadPackets = htonll(c->NoWorkloadPackets);
    c->IPv4Packets = htonll(c->IPv4Packets);
    c->IPv6Packets = htonll(c->IPv6Packets);
    c->TCPPackets = htonll(c->TCPPackets);
    c->TCPNoSessionPackets = htonll(c->TCPNoSessionPackets);
    c->UDPPackets = htonll(c->UDPPackets);
    c->ICMPPackets = htonll(c->ICMPPackets);
    c->OtherPackets = htonll(c->OtherPackets);
    c->Assemblys = htonll(c->Assemblys);
    c->FreedAssemblys = htonll(c->FreedAssemblys);
    c->Fragments = htonll(c->Fragments);
    c->FreedFragments = htonll(c->FreedFragments);
    c->TimeoutFragments = htonll(c->TimeoutFragments);

    c->TotalSessions = htonll(c->TotalSessions);
    c->TCPSessions = htonll(c->TCPSessions);
    c->UDPSessions = htonll(c->UDPSessions);
    c->ICMPSessions = htonll(c->ICMPSessions);
    c->IPSessions = htonll(c->IPSessions);

    c->DropMeters = htonll(c->DropMeters);
    c->ProxyMeters = htonll(c->ProxyMeters);
    c->CurMeters = htonll(c->CurMeters);
    c->CurLogCaches = htonll(c->CurLogCaches);

    int j = 0;
    for (j = 0; j < DPI_PARSER_MAX; j ++) {
        c->ParserSessions[j] = htonll(c->ParserSessions[j]);
        c->ParserPackets[j] = htonll(c->ParserPackets[j]);
    }

    c->PolicyType1Rules = htonl(c->PolicyType1Rules);
    c->PolicyType2Rules = htonl(c->PolicyType2Rules);
    c->PolicyDomains = htonl(c->PolicyDomains);
    c->PolicyDomainIPs = htonl(c->PolicyDomainIPs);

    // Get conn stats
    conn_stats_t cs;
    memset(&cs, 0, sizeof(cs));
    dp_read_conn_stats(&cs, 0);

    c->LimitDropConns = htonll(cs.limit_drop);
    c->LimitPassConns = htonll(cs.limit_pass);

    // Get ring stats
    dp_stats_t s;
    memset(&s, 0, sizeof(s));
    dp_read_ring_stats(&s, 0);

    c->RXPackets = htonll(s.rx);
    c->TXPackets = htonll(s.tx);
    c->RXDropPackets = htonll(s.rx_drops);
    c->TXDropPackets = htonll(s.tx_drops);

    dp_ctrl_send_binary(buf, sizeof(buf));

    return 0;
}

static int dp_ctrl_count_session(json_t *msg)
{
    uint8_t buf[sizeof(DPMsgHdr) + sizeof(DPMsgSessionCount)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_SESSION_COUNT;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(DPMsgSessionCount));
    hdr->More = 0;

    DPMsgSessionCount *count = (DPMsgSessionCount *)(buf + sizeof(DPMsgHdr));
    memset(count, 0, sizeof(*count));
    dpi_count_session(count);
    count->CurSess = htonl(count->CurSess);
    count->CurTCPSess = htonl(count->CurTCPSess);
    count->CurUDPSess = htonl(count->CurUDPSess);
    count->CurICMPSess = htonl(count->CurICMPSess);
    count->CurIPSess = htonl(count->CurIPSess);

    dp_ctrl_send_binary(buf, sizeof(buf));

    return 0;
}

static int dp_ctrl_list_session(json_t *msg)
{
    int thr_id;
    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_data_wait_ctrl_req_thr(CTRL_REQ_LIST_SESSION, thr_id);
    }

    uint8_t buf[sizeof(DPMsgHdr) + sizeof(DPMsgSessionHdr)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_SESSION_LIST;
    hdr->Length = htons(sizeof(hdr));
    hdr->More = 0;

    DPMsgSessionHdr *sh = (DPMsgSessionHdr *)(buf + sizeof(DPMsgHdr));
    sh->Sessions = 0;

    dp_ctrl_send_binary(buf, sizeof(buf));

    return 0;
}

uint32_t g_sess_id_to_clear = 0;

static int dp_ctrl_clear_session(json_t *msg)
{
    g_sess_id_to_clear = json_integer_value(json_object_get(msg, "filter_id"));
    DEBUG_CTRL("clear session %d\n", g_sess_id_to_clear);

    int thr_id;
    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_data_wait_ctrl_req_thr(CTRL_REQ_CLEAR_SESSION, thr_id);
    }

    g_sess_id_to_clear = 0;
    return 0;
}

static int dp_ctrl_list_meter(json_t *msg)
{
    int thr_id;
    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_data_wait_ctrl_req_thr(CTRL_REQ_LIST_METER, thr_id);
    }

    uint8_t buf[sizeof(DPMsgHdr) + sizeof(DPMsgMeterHdr)];

    DPMsgHdr *hdr = (DPMsgHdr *)buf;
    hdr->Kind = DP_KIND_METER_LIST;
    hdr->Length = htons(sizeof(hdr));
    hdr->More = 0;

    DPMsgMeterHdr *mh = (DPMsgMeterHdr *)(buf + sizeof(DPMsgHdr));
    mh->Meters = 0;

    dp_ctrl_send_binary(buf, sizeof(buf));

    return 0;
}

static int dp_ctrl_set_debug(json_t *msg)
{
    json_t *cats = json_object_get(msg, "categories");
    if (json_is_array(cats)) {
        int i;
        uint32_t levels = 0;

        for (i = 0; i < json_array_size(cats); i ++) {
            const char *cat = json_string_value(json_array_get(cats, i));
            levels |= debug_name2level(cat);
        }

        g_debug_levels = levels | DBG_DEFAULT;
    }

    return 0;
}

/*
static int dp_ctrl_get_debug(json_t *msg)
{
    json_t *cats = json_array();
    if (cats == NULL) {
        json_t *root = json_pack("{s:{s:[]}}", "dp_debug", "categories");
        dp_ctrl_send_json(root);
        return -1;
    }

    uint32_t levels = g_debug_levels;
    if (levels & DBG_INIT) {
        json_array_append_new(cats, json_string("init"));
    }
    if (levels & DBG_ERROR) {
        json_array_append_new(cats, json_string("error"));
    }
    if (levels & DBG_CTRL) {
        json_array_append_new(cats, json_string("ctrl"));
    }
    if (levels & DBG_PACKET) {
        json_array_append_new(cats, json_string("packet"));
    }
    if (levels & DBG_SESSION) {
        json_array_append_new(cats, json_string("session"));
    }
    if (levels & DBG_TIMER) {
        json_array_append_new(cats, json_string("timer"));
    }
    if (levels & DBG_TCP) {
        json_array_append_new(cats, json_string("tcp"));
    }
    if (levels & DBG_PARSER) {
        json_array_append_new(cats, json_string("parser"));
    }
    if (levels & DBG_LOG) {
        json_array_append_new(cats, json_string("log"));
    }
    if (levels & DBG_DDOS) {
        json_array_append_new(cats, json_string("ddos"));
    }

    // "steal" array's reference
    json_t *root = json_pack("{s:{s:o}}", "dp_debug", "categories", cats);
    if (dp_ctrl_send_json(root) < 0) {
        json_decref(cats);
        return -1;
    }

    return 0;
}
*/


static int dp_ctrl_cfg_policy(json_t *msg)
{
    int cmd;
    json_t *obj, *rule_obj, *app_obj, *app_rule_obj;
    dpi_policy_t policy;
    int i, j;
    int flag;
    int ret = 0;

    cmd = json_integer_value(json_object_get(msg, "cmd"));
    flag = json_integer_value(json_object_get(msg, "flag"));
    policy.def_action = json_integer_value(json_object_get(msg, "defact"));
    policy.apply_dir = json_integer_value(json_object_get(msg, "dir"));

    obj = json_object_get(msg, "mac");
    policy.num_macs = json_array_size(obj);
    if (!policy.num_macs) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in policy cfg!!\n");
        return -1;
    }
    policy.mac_list = calloc(sizeof(struct ether_addr), policy.num_macs);
    if (!policy.mac_list) {
        DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
        return -1;
    }

    for (i = 0; i < policy.num_macs; i++) {
        const char *mac_str = json_string_value(json_array_get(obj, i));
        ether_aton_r(mac_str, &policy.mac_list[i]);
    }

    obj = json_object_get(msg, "rules");
    policy.num_rules = json_array_size(obj);
    if (policy.num_rules) {
        policy.rule_list = calloc(policy.num_rules, sizeof(dpi_policy_rule_t));
        if (!policy.rule_list) {
            DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
            free(policy.mac_list);
            return -1;
        }
    } else {
        policy.rule_list = NULL;
    }

    for (i = 0; i < policy.num_rules; i ++) {
        json_t *ip_obj, *fqdn_obj;
        rule_obj = json_array_get(obj, i);
        policy.rule_list[i].id = json_integer_value(json_object_get(rule_obj, "id"));
        policy.rule_list[i].sip = inet_addr(json_string_value(json_object_get(rule_obj, "sip")));
        policy.rule_list[i].dip = inet_addr(json_string_value(json_object_get(rule_obj, "dip")));
        ip_obj = json_object_get(rule_obj, "sipr");
        if (ip_obj) {
            policy.rule_list[i].sip_r = inet_addr(json_string_value(ip_obj));
        } else {
            policy.rule_list[i].sip_r = policy.rule_list[i].sip;
        }
        ip_obj = json_object_get(rule_obj, "dipr");
        if (ip_obj) {
            policy.rule_list[i].dip_r = inet_addr(json_string_value(ip_obj));
        } else {
            policy.rule_list[i].dip_r = policy.rule_list[i].dip;
        }
        policy.rule_list[i].dport = json_integer_value(json_object_get(rule_obj, "port"));
        policy.rule_list[i].dport_r = json_integer_value(json_object_get(rule_obj, "portr"));
        policy.rule_list[i].proto = json_integer_value(json_object_get(rule_obj, "proto"));
        policy.rule_list[i].action = json_integer_value(json_object_get(rule_obj, "action"));
        policy.rule_list[i].ingress = json_boolean_value(json_object_get(rule_obj, "ingress"));
        policy.rule_list[i].vh = json_boolean_value(json_object_get(rule_obj, "vhost"));
        fqdn_obj = json_object_get(rule_obj,"fqdn");
        if (fqdn_obj != NULL) {
            strlcpy(policy.rule_list[i].fqdn, json_string_value(fqdn_obj), MAX_FQDN_LEN);
        }
        app_obj = json_object_get(rule_obj,"apps");
        if (app_obj != NULL) {
            int num_apps = json_array_size(app_obj);
            dpi_policy_app_rule_t *app_rule = calloc(num_apps, sizeof(dpi_policy_app_rule_t));
            if (!app_rule) {
                DEBUG_ERROR(DBG_CTRL, "out of memory!!\n");
                ret = -1;
                goto cleanup;
            }
            policy.rule_list[i].num_apps = num_apps;
            policy.rule_list[i].app_rules = app_rule;
            for (j = 0; j < num_apps; j++) {
                app_rule_obj = json_array_get(app_obj, j);
                app_rule->rule_id = json_integer_value(json_object_get(app_rule_obj, "rid"));
                app_rule->app = json_integer_value(json_object_get(app_rule_obj, "app"));
                app_rule->action = json_integer_value(json_object_get(app_rule_obj, "action"));
                app_rule++;
            }
        }
    }

    dpi_policy_cfg(cmd, &policy, flag);
cleanup:
    free(policy.mac_list);
    if (policy.rule_list) {
        for (i = 0; i < policy.num_rules; i ++) {
            if (policy.rule_list[i].app_rules)  {
                free(policy.rule_list[i].app_rules);
            }
        }
        free(policy.rule_list);
    }
    return ret;
}

static int dp_ctrl_set_fqdn(json_t *msg)
{
    int i, count;
    char fqdname[MAX_FQDN_LEN];
    json_t *obj;
    uint32_t fqdnip;
    json_t *vhost_obj;
    bool vhost = false;

    vhost_obj = json_object_get(msg, "vhost");
    if (vhost_obj != NULL) {
        vhost = json_boolean_value(vhost_obj);
    }

    strlcpy(fqdname, json_string_value(json_object_get(msg, "fqdn_name")), MAX_FQDN_LEN);
    obj = json_object_get(msg, "fqdn_ips");
    count = json_array_size(obj);

    rcu_read_lock();
    for (i = 0; i < count; i++) {
        fqdnip = inet_addr(json_string_value(json_array_get(obj, i)));
        //DEBUG_CTRL("fqdn(%s) vhost(%d) => "DBG_IPV4_FORMAT"\n", fqdname, vhost, DBG_IPV4_TUPLE(fqdnip));
        config_fqdn_ipv4_mapping(g_fqdn_hdl, fqdname, fqdnip, vhost);
    }
    rcu_read_unlock();

    return 0;
}

static int dp_ctrl_del_fqdn(json_t *msg)
{
    int i, count;
    json_t *obj;
    const char *name;

    obj = json_object_get(msg, "names");
    count = json_array_size(obj);
    for (i = 0; i < count; i++) {
        name = json_string_value(json_array_get(obj, i));
        dpi_fqdn_entry_mark_delete(name);
    }
    dpi_fqdn_entry_delete_marked();
    return 0;
}

io_internal_subnet4_t *g_internal_subnet4;
io_internal_subnet4_t *g_policy_addr;

//internal:true for internalSubnet, false for policy address map
static int dp_ctrl_cfg_internal_net(json_t *msg, bool internal)
{
    int i, count;
    json_t *obj, *nw_obj;
    io_internal_subnet4_t *subnet4, *old, *tsubnet4;
    static io_internal_subnet4_t *t_internal_subnet4 = NULL;
    int flag;
    bool multiple_msg = false;

    flag = json_integer_value(json_object_get(msg, "flag"));
    obj = json_object_get(msg, "subnet_addr");
    count = json_array_size(obj);

    subnet4 = calloc(sizeof(io_internal_subnet4_t) + count * sizeof(io_subnet4_t), 1);
    if (!subnet4) {
        DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
        return -1;
    }

    subnet4->count = count;
    for (i = 0; i < count; i++) {
        nw_obj = json_array_get(obj, i);
        subnet4->list[i].ip = inet_addr(json_string_value(json_object_get(nw_obj, "ip")));
        subnet4->list[i].mask = inet_addr(json_string_value(json_object_get(nw_obj, "mask")));
    }

    if (flag & MSG_START) {
        //static pointer to remember allocated memory address
        t_internal_subnet4 = subnet4;
    } else {
        if (!t_internal_subnet4) {
            if (internal) {
                DEBUG_ERROR(DBG_CTRL, "missed internal ip msg start!\n");
            } else {
                DEBUG_ERROR(DBG_CTRL, "missed policy addr msg start!\n");
            }
            free(subnet4);
            return -1;
        }
        tsubnet4 = calloc(sizeof(io_internal_subnet4_t) + (t_internal_subnet4->count + count) * sizeof(io_subnet4_t), 1);
        if (!tsubnet4) {
            DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
            return -1;
        }
        memcpy(&tsubnet4->list[0], &t_internal_subnet4->list[0], sizeof(io_subnet4_t) * t_internal_subnet4->count);
        memcpy(&tsubnet4->list[t_internal_subnet4->count], &subnet4->list[0], sizeof(io_subnet4_t) * subnet4->count);
        tsubnet4->count = t_internal_subnet4->count + count;
        free(subnet4);
        free(t_internal_subnet4);
        t_internal_subnet4 = tsubnet4;
        multiple_msg = true;
    }

    if (!(flag & MSG_END)) {
        return 0;
    }

    if (internal) {
        old = g_internal_subnet4;
    } else {
        old = g_policy_addr;
    }
    if (multiple_msg) {
        if (internal) {
            g_internal_subnet4 = tsubnet4;
        } else {
            g_policy_addr = tsubnet4;
        }
    } else {
        if (internal) {
            g_internal_subnet4 = subnet4;
        } else {
            g_policy_addr = subnet4;
        }
    }

    synchronize_rcu();

    free(old);

    return 0;
}

io_spec_internal_subnet4_t *g_specialip_subnet4;

static int dp_ctrl_cfg_specialip_net(json_t *msg)
{
    int i, count;
    json_t *obj, *nw_obj;
    io_spec_internal_subnet4_t *subnet4, *old, *tsubnet4;
    static io_spec_internal_subnet4_t *t_specialip_subnet4 = NULL;
    int flag;
    bool multiple_msg = false;

    flag = json_integer_value(json_object_get(msg, "flag"));
    obj = json_object_get(msg, "subnet_addr");
    count = json_array_size(obj);

    subnet4 = calloc(sizeof(io_spec_internal_subnet4_t) + count * sizeof(io_spec_subnet4_t), 1);
    if (!subnet4) {
        DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
        return -1;
    }

    subnet4->count = count;
    for (i = 0; i < count; i++) {
        nw_obj = json_array_get(obj, i);
        subnet4->list[i].ip = inet_addr(json_string_value(json_object_get(nw_obj, "ip")));
        subnet4->list[i].mask = inet_addr(json_string_value(json_object_get(nw_obj, "mask")));
        const char *iptype = json_string_value(json_object_get(nw_obj, "iptype"));
        if (strcasecmp(iptype, SPEC_INTERNAL_TUNNELIP) == 0) {
            subnet4->list[i].iptype = DP_IPTYPE_TUNNELIP;
        } else if (strcasecmp(iptype, SPEC_INTERNAL_SVCIP) == 0) {
            subnet4->list[i].iptype = DP_IPTYPE_SVCIP;
        } else if (strcasecmp(iptype, SPEC_INTERNAL_HOSTIP) == 0) {
            subnet4->list[i].iptype = DP_IPTYPE_HOSTIP;
        } else if (strcasecmp(iptype, SPEC_INTERNAL_DEVIP) == 0) {
            subnet4->list[i].iptype = DP_IPTYPE_DEVIP;
        } else if (strcasecmp(iptype, SPEC_INTERNAL_UWLIP) == 0) {
            subnet4->list[i].iptype = DP_IPTYPE_UWLIP;
        } else if (strcasecmp(iptype, SPEC_INTERNAL_EXTIP) == 0) {
            subnet4->list[i].iptype = DP_IPTYPE_EXTIP;
        } else {
            subnet4->list[i].iptype = DP_IPTYPE_NONE;
        }
        DEBUG_CTRL("iptypestr=%s iptypeval=%d\n", iptype, subnet4->list[i].iptype);
    }

    if (flag & MSG_START) {
        //static pointer to remember allocated memory address
        t_specialip_subnet4 = subnet4;
    } else {
        if (!t_specialip_subnet4) {
            DEBUG_ERROR(DBG_CTRL, "missed special ip msg start!\n");
            free(subnet4);
            return -1;
        }
        tsubnet4 = calloc(sizeof(io_spec_internal_subnet4_t) + (t_specialip_subnet4->count + count) * sizeof(io_spec_subnet4_t), 1);
        if (!tsubnet4) {
            DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
            return -1;
        }
        memcpy(&tsubnet4->list[0], &t_specialip_subnet4->list[0], sizeof(io_spec_subnet4_t) * t_specialip_subnet4->count);
        memcpy(&tsubnet4->list[t_specialip_subnet4->count], &subnet4->list[0], sizeof(io_spec_subnet4_t) * subnet4->count);
        tsubnet4->count = t_specialip_subnet4->count + count;
        free(subnet4);
        free(t_specialip_subnet4);
        t_specialip_subnet4 = tsubnet4;
        multiple_msg = true;
    }

    if (!(flag & MSG_END)) {
        return 0;
    }

    old = g_specialip_subnet4;
    if (multiple_msg) {
        g_specialip_subnet4 = tsubnet4;
    } else {
        g_specialip_subnet4 = subnet4;
    }

    synchronize_rcu();

    free(old);

    return 0;
}

//dlp

static int dp_ctrl_del_dlp(json_t *msg)
{
    json_t *obj;
    int len, i;
    struct cds_lfht_node *dlpcfg_node_list[MAX_DLPCFG_DELETE];
    struct cds_lfht_node *wafcfg_node_list[MAX_DLPCFG_DELETE];
    struct cds_lfht_node *dlprid_node_list[MAX_DLPCFG_DELETE];
    struct cds_lfht_node *wafrid_node_list[MAX_DLPCFG_DELETE];
    int cnt = 0;
    int cnt1 = 0;
    int cnt2 = 0;
    int cnt3 = 0;

    obj = json_object_get(msg, "delmac");

    len = json_array_size(obj);
    if (len == 0) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in dlp del mac!!\n");
        return -1;
    }

    rcu_read_lock();
    for (i = 0; i < len; i ++) {
        struct ether_addr mac_addr;
        const char *mac_str = json_string_value(json_array_get(obj, i));
        ether_aton_r(mac_str, &mac_addr);
        io_mac_t *mac = rcu_map_lookup(&g_ep_map, &mac_addr);
        if (mac == NULL) {
            DEBUG_ERROR(DBG_CTRL, "dlp del mac %s not found in ep map.\n", mac_str);
            continue;
        }

        io_ep_t *ep = mac->ep;
        struct cds_lfht_node *dlp_cfg_node;
        struct cds_lfht_node *waf_cfg_node;
        struct cds_lfht_node *dlp_rid_node;
        struct cds_lfht_node *waf_rid_node;

        do {
            RCU_MAP_FOR_EACH(&ep->dlp_cfg_map, dlp_cfg_node) {
                io_dlp_cfg_t *dlp_conf = STRUCT_OF(dlp_cfg_node, io_dlp_cfg_t, node);
                if (cnt < MAX_DLPCFG_DELETE) {
                    DEBUG_CTRL("remove dlp config %u from ep[%d]: mac:(%s) dlp config map.\n",
                        dlp_conf->sigid, i, mac_str);
                    rcu_map_del(&ep->dlp_cfg_map, dlp_cfg_node);
                    dlpcfg_node_list[cnt] = dlp_cfg_node;
                    cnt++;
                }
            }
        } while (0);

        do {
            RCU_MAP_FOR_EACH(&ep->dlp_rid_map, dlp_rid_node) {
                io_dlp_ruleid_t *dlp_rid = STRUCT_OF(dlp_rid_node, io_dlp_ruleid_t, node);
                if (cnt1 < MAX_DLPCFG_DELETE) {
                    DEBUG_CTRL("remove dlp rid %d from ep[%d]: mac:(%s) dlp rid map.\n",
                        dlp_rid->rid, i, mac_str);
                    rcu_map_del(&ep->dlp_rid_map, dlp_rid_node);
                    dlprid_node_list[cnt1] = dlp_rid_node;
                    cnt1++;
                }
            }            
        } while (0);

        do {
            RCU_MAP_FOR_EACH(&ep->waf_cfg_map, waf_cfg_node) {
                io_dlp_cfg_t *waf_conf = STRUCT_OF(waf_cfg_node, io_dlp_cfg_t, node);
                if (cnt2 < MAX_DLPCFG_DELETE) {
                    DEBUG_CTRL("remove waf config %u from ep[%d]: mac:(%s) waf config map.\n",
                        waf_conf->sigid, i, mac_str);
                    rcu_map_del(&ep->waf_cfg_map, waf_cfg_node);
                    wafcfg_node_list[cnt2] = waf_cfg_node;
                    cnt2++;
                }
            }
        } while (0);

        do {
            RCU_MAP_FOR_EACH(&ep->waf_rid_map, waf_rid_node) {
                io_dlp_ruleid_t *waf_rid = STRUCT_OF(waf_rid_node, io_dlp_ruleid_t, node);
                if (cnt3 < MAX_DLPCFG_DELETE) {
                    DEBUG_CTRL("remove waf rid %d from ep[%d]: mac:(%s) waf rid map.\n",
                        waf_rid->rid, i, mac_str);
                    rcu_map_del(&ep->waf_rid_map, waf_rid_node);
                    wafrid_node_list[cnt3] = waf_rid_node;
                    cnt3++;
                }
            }            
        } while (0);

    }
    rcu_read_unlock();
    if ( cnt > 0 || cnt1 > 0 || cnt2 >0 || cnt3 > 0 ) {
        synchronize_rcu();
        for (i = 0; i < cnt; i++) {
            io_dlp_cfg_t *dlp_cfg_ptr = STRUCT_OF(dlpcfg_node_list[i], io_dlp_cfg_t, node);
            if (dlp_cfg_ptr->sig_user_list.prev == NULL && dlp_cfg_ptr->sig_user_list.next == NULL) {
                CDS_INIT_LIST_HEAD(&dlp_cfg_ptr->sig_user_list);
            }
            dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
            cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &dlp_cfg_ptr->sig_user_list, node) {
                cds_list_del((struct cds_list_head *)sig_user_itr);
                if (sig_user_itr->sig_user) {
                    free(sig_user_itr->sig_user);
                }
                free(sig_user_itr);
            }
            free(dlpcfg_node_list[i]);
        }
        for (i = 0; i < cnt1; i++) {
            free(dlprid_node_list[i]);
        }
        for (i = 0; i < cnt2; i++) {
            io_dlp_cfg_t *waf_cfg_ptr = STRUCT_OF(wafcfg_node_list[i], io_dlp_cfg_t, node);
            if (waf_cfg_ptr->sig_user_list.prev == NULL && waf_cfg_ptr->sig_user_list.next == NULL) {
                CDS_INIT_LIST_HEAD(&waf_cfg_ptr->sig_user_list);
            }
            dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
            cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &waf_cfg_ptr->sig_user_list, node) {
                cds_list_del((struct cds_list_head *)sig_user_itr);
                if (sig_user_itr->sig_user) {
                    free(sig_user_itr->sig_user);
                }
                free(sig_user_itr);
            }
            free(wafcfg_node_list[i]);
        }
        for (i = 0; i < cnt3; i++) {
            free(wafrid_node_list[i]);
        }
    }
    return 0;
}

static int dp_ctrl_cfg_dlp(json_t *msg)
{
    json_t *obj, *dlp_rulename_obj, *rule_ids_obj, *waf_rulename_obj, *waf_rule_ids_obj;
    int len, i;
    struct cds_lfht_node *dlpcfg_node_list[MAX_DLPCFG_DELETE];
    struct cds_lfht_node *wafcfg_node_list[MAX_DLPCFG_DELETE];
    struct cds_lfht_node *dlprid_node_list[MAX_DLPCFG_DELETE];
    struct cds_lfht_node *wafrid_node_list[MAX_DLPCFG_DELETE];
    int cnt = 0;
    int cnt1 = 0;
    int cnt2 = 0;
    int cnt3 = 0;
    int flag;
    const char *ruletype = json_string_value(json_object_get(msg, "ruletype"));
    const char *wafruletype = json_string_value(json_object_get(msg, "wafruletype"));
    bool inside_rule = false;
    bool wafinside_rule = false;

    if ( strcmp(ruletype, DLP_RULETYPE_INSIDE) == 0 ) {
        inside_rule = true;
    } else if ( strcmp(ruletype, DLP_RULETYPE_OUTSIDE) == 0 ) {
        inside_rule = false;
    }
    if ( strcmp(wafruletype, WAF_RULETYPE_INSIDE) == 0 ) {
        wafinside_rule = true;
    } else if ( strcmp(wafruletype, WAF_RULETYPE_OUTSIDE) == 0 ) {
        wafinside_rule = false;
    } 
    DEBUG_CTRL("ruletype %s, wafruletype %s, inside_rule %d, wafinside_rule %d\n", ruletype, wafruletype, inside_rule, wafinside_rule);

    obj = json_object_get(msg, "mac");
    flag = json_integer_value(json_object_get(msg, "flag"));
    dlp_rulename_obj = json_object_get(msg, "dlp_rule_names");
    waf_rulename_obj = json_object_get(msg, "waf_rule_names");
    rule_ids_obj = json_object_get(msg, "rule_ids");
    waf_rule_ids_obj = json_object_get(msg, "waf_rule_ids");

    len = json_array_size(obj);
    if (len == 0) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in dlp cfg rulenames!!\n");
        return -1;
    }

    rcu_read_lock();
    for (i = 0; i < len; i ++) {
        struct ether_addr mac_addr;
        const char *mac_str = json_string_value(json_array_get(obj, i));
        ether_aton_r(mac_str, &mac_addr);
        io_mac_t *mac = rcu_map_lookup(&g_ep_map, &mac_addr);
        if (mac == NULL) {
            DEBUG_ERROR(DBG_CTRL, "dlp cfg mac %s not found in ep map.\n", mac_str);
            continue;
        }

        io_ep_t *ep = mac->ep;
        ep->dlp_inside = inside_rule;
        ep->waf_inside = wafinside_rule;
        // policy ids/connection to be exempt of dlp check
        if ((flag & MSG_START) && rule_ids_obj != NULL) {
            int k;
            struct cds_lfht_node *dlp_rid_node;
            //disalbe previous configured rids
            RCU_MAP_FOR_EACH(&ep->dlp_rid_map, dlp_rid_node) {
                io_dlp_ruleid_t *dlprid = STRUCT_OF(dlp_rid_node, io_dlp_ruleid_t, node);
                if (dlprid->enable) {
                    dlprid->enable = false;
                }
            }
            for (k = 0; k < json_array_size(rule_ids_obj); k++) {
                uint32_t rid = json_integer_value(json_array_get(rule_ids_obj, k));
                io_dlp_ruleid_t ridkey;
                ridkey.rid = rid;

                io_dlp_ruleid_t *dlp_ruleid = rcu_map_lookup(&ep->dlp_rid_map, &ridkey);
                if (dlp_ruleid == NULL) {//new rid
                    if ((dlp_ruleid = calloc(1, sizeof(*dlp_ruleid))) != NULL) {
                        dlp_ruleid->rid = ridkey.rid;
                        dlp_ruleid->enable = true;
                        rcu_map_add(&ep->dlp_rid_map, dlp_ruleid, dlp_ruleid);
                    }
                } else if (!dlp_ruleid->enable) {
                    dlp_ruleid->enable = true;
                    //dlp_ruleid->rid = ridkey.rid;
                }
            }
            do {
                RCU_MAP_FOR_EACH(&ep->dlp_rid_map, dlp_rid_node) {
                    io_dlp_ruleid_t *dlprid = STRUCT_OF(dlp_rid_node, io_dlp_ruleid_t, node);
                    if (!dlprid->enable && cnt1 < MAX_DLPCFG_DELETE) {
                        DEBUG_CTRL("remove dlp ruleid %d from ep %s dlp ruleid map.\n",
                            dlprid->rid, mac_str);
                        rcu_map_del(&ep->dlp_rid_map, dlp_rid_node);
                        dlprid_node_list[cnt1] = dlp_rid_node;
                        cnt1++;
                    }
                }
            } while (0);
        }

        //waf
        if ((flag & MSG_START) && waf_rule_ids_obj != NULL) {
            int k;
            struct cds_lfht_node *waf_rid_node;
            //disalbe previous configured rids
            RCU_MAP_FOR_EACH(&ep->waf_rid_map, waf_rid_node) {
                io_dlp_ruleid_t *wafrid = STRUCT_OF(waf_rid_node, io_dlp_ruleid_t, node);
                if (wafrid->enable) {
                    wafrid->enable = false;
                }
            }
            for (k = 0; k < json_array_size(waf_rule_ids_obj); k++) {
                uint32_t wafrid = json_integer_value(json_array_get(waf_rule_ids_obj, k));
                io_dlp_ruleid_t wafridkey;
                wafridkey.rid = wafrid;

                io_dlp_ruleid_t *waf_ruleid = rcu_map_lookup(&ep->waf_rid_map, &wafridkey);
                if (waf_ruleid == NULL) {//new rid
                    if ((waf_ruleid = calloc(1, sizeof(*waf_ruleid))) != NULL) {
                        waf_ruleid->rid = wafridkey.rid;
                        waf_ruleid->enable = true;
                        rcu_map_add(&ep->waf_rid_map, waf_ruleid, waf_ruleid);
                    }
                } else if (!waf_ruleid->enable) {
                    waf_ruleid->enable = true;
                    //waf_ruleid->rid = wafridkey.rid;
                }
            }
            do {
                RCU_MAP_FOR_EACH(&ep->waf_rid_map, waf_rid_node) {
                    io_dlp_ruleid_t *wafrid = STRUCT_OF(waf_rid_node, io_dlp_ruleid_t, node);
                    if (!wafrid->enable && cnt2 < MAX_DLPCFG_DELETE) {
                        DEBUG_CTRL("remove waf ruleid %d from ep %s waf ruleid map.\n",
                            wafrid->rid, mac_str);
                        rcu_map_del(&ep->waf_rid_map, waf_rid_node);
                        wafrid_node_list[cnt2] = waf_rid_node;
                        cnt2++;
                    }
                }
            } while (0);
        }

        // dlp rule names
        if (dlp_rulename_obj != NULL) {
            int j;
            struct cds_lfht_node *dlp_cfg_node;
            if (flag & MSG_START) {
                RCU_MAP_FOR_EACH(&ep->dlp_cfg_map, dlp_cfg_node) {
                    io_dlp_cfg_t *dlpcfg = STRUCT_OF(dlp_cfg_node, io_dlp_cfg_t, node);
                    if (dlpcfg->enable) {
                        dlpcfg->enable = false;
                    }
                }
            }
            for (j = 0; j < json_array_size(dlp_rulename_obj); j++) {
                json_t *dlprn = json_array_get(dlp_rulename_obj, j);
                io_dlp_cfg_t key;
                key.sigid = json_integer_value(json_object_get(dlprn, "id"));
                key.action = json_integer_value(json_object_get(dlprn, "action"));

                io_dlp_cfg_t *dlp_cfg = rcu_map_lookup(&ep->dlp_cfg_map, &key);
                if (dlp_cfg == NULL) {
                    if ((dlp_cfg = calloc(1, sizeof(*dlp_cfg))) != NULL) {
                        dlp_cfg->sigid = key.sigid;
                        dlp_cfg->action = key.action;
                        dlp_cfg->enable = true;
                        rcu_map_add(&ep->dlp_cfg_map, dlp_cfg, dlp_cfg);
                    }
                } else if (!dlp_cfg->enable) {
                    dlp_cfg->enable = true;
                    dlp_cfg->action = key.action;
                }
            }
            if (flag & MSG_END) {
                do {
                    RCU_MAP_FOR_EACH(&ep->dlp_cfg_map, dlp_cfg_node) {
                        io_dlp_cfg_t *dlp_conf = STRUCT_OF(dlp_cfg_node, io_dlp_cfg_t, node);
                        if (!dlp_conf->enable && cnt < MAX_DLPCFG_DELETE) {
                            DEBUG_CTRL("remove dlp config %u from ep %s dlp config map.\n",
                                dlp_conf->sigid, mac_str);
                            rcu_map_del(&ep->dlp_cfg_map, dlp_cfg_node);
                            dlpcfg_node_list[cnt] = dlp_cfg_node;
                            cnt++;
                        }
                    }
                } while (0);
            }
        }

        // waf rule names
        if (waf_rulename_obj != NULL) {
            int j;
            struct cds_lfht_node *waf_cfg_node;
            if (flag & MSG_START) {
                RCU_MAP_FOR_EACH(&ep->waf_cfg_map, waf_cfg_node) {
                    io_dlp_cfg_t *wafcfg = STRUCT_OF(waf_cfg_node, io_dlp_cfg_t, node);
                    if (wafcfg->enable) {
                        wafcfg->enable = false;
                    }
                }
            }
            for (j = 0; j < json_array_size(waf_rulename_obj); j++) {
                json_t *wafrn = json_array_get(waf_rulename_obj, j);
                io_dlp_cfg_t wafkey;
                wafkey.sigid = json_integer_value(json_object_get(wafrn, "id"));
                wafkey.action = json_integer_value(json_object_get(wafrn, "action"));

                io_dlp_cfg_t *waf_cfg = rcu_map_lookup(&ep->waf_cfg_map, &wafkey);
                if (waf_cfg == NULL) {
                    if ((waf_cfg = calloc(1, sizeof(*waf_cfg))) != NULL) {
                        waf_cfg->sigid = wafkey.sigid;
                        waf_cfg->action = wafkey.action;
                        waf_cfg->enable = true;
                        rcu_map_add(&ep->waf_cfg_map, waf_cfg, waf_cfg);
                    }
                } else if (!waf_cfg->enable) {
                    waf_cfg->enable = true;
                    waf_cfg->action = wafkey.action;
                }
            }
            if (flag & MSG_END) {
                do {
                    RCU_MAP_FOR_EACH(&ep->waf_cfg_map, waf_cfg_node) {
                        io_dlp_cfg_t *waf_conf = STRUCT_OF(waf_cfg_node, io_dlp_cfg_t, node);
                        if (!waf_conf->enable && cnt3 < MAX_DLPCFG_DELETE) {
                            DEBUG_CTRL("remove waf config %u from ep %s waf config map.\n",
                                waf_conf->sigid, mac_str);
                            rcu_map_del(&ep->waf_cfg_map, waf_cfg_node);
                            wafcfg_node_list[cnt3] = waf_cfg_node;
                            cnt3++;
                        }
                    }
                } while (0);
            }
        }
    }
    rcu_read_unlock();
    if ( cnt > 0 || cnt1 > 0 || cnt2 >0 || cnt3 > 0 ) {
        synchronize_rcu();
        for (i = 0; i < cnt; i++) {
            io_dlp_cfg_t *dlp_cfg_ptr = STRUCT_OF(dlpcfg_node_list[i], io_dlp_cfg_t, node);
            if (dlp_cfg_ptr->sig_user_list.prev == NULL && dlp_cfg_ptr->sig_user_list.next == NULL) {
                CDS_INIT_LIST_HEAD(&dlp_cfg_ptr->sig_user_list);
            }
            dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
            cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &dlp_cfg_ptr->sig_user_list, node) {
                cds_list_del((struct cds_list_head *)sig_user_itr);
                if (sig_user_itr->sig_user) {
                    free(sig_user_itr->sig_user);
                }
                free(sig_user_itr);
            }
            free(dlpcfg_node_list[i]);
        }
        for (i = 0; i < cnt3; i++) {
            io_dlp_cfg_t *waf_cfg_ptr = STRUCT_OF(wafcfg_node_list[i], io_dlp_cfg_t, node);
            if (waf_cfg_ptr->sig_user_list.prev == NULL && waf_cfg_ptr->sig_user_list.next == NULL) {
                CDS_INIT_LIST_HEAD(&waf_cfg_ptr->sig_user_list);
            }
            dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
            cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &waf_cfg_ptr->sig_user_list, node) {
                cds_list_del((struct cds_list_head *)sig_user_itr);
                if (sig_user_itr->sig_user) {
                    free(sig_user_itr->sig_user);
                }
                free(sig_user_itr);
            }
            free(wafcfg_node_list[i]);
        }
        for (i = 0; i < cnt1; i++) {
            free(dlprid_node_list[i]);
        }
        for (i = 0; i < cnt2; i++) {
            free(wafrid_node_list[i]);
        }
    }

    return 0;
}

static int dp_ctrl_bld_dlp(json_t *msg)
{
    int flag;
    json_t *obj, *rule_obj, *pat_obj;
    dpi_dlpbld_t dlpbld;
    int i, j;
    int ret = 0;

    flag = json_integer_value(json_object_get(msg, "flag"));
    dlpbld.apply_dir = json_integer_value(json_object_get(msg, "dir"));

    //get workload mac list
    obj = json_object_get(msg, "mac");
    dlpbld.num_macs = json_array_size(obj);

    DEBUG_CTRL("# of macs(%d) bld dlp\n", dlpbld.num_macs);
    if (dlpbld.num_macs > 0) {
        dlpbld.mac_list = calloc(sizeof(struct ether_addr), dlpbld.num_macs);
        if (!dlpbld.mac_list) {
            DEBUG_ERROR(DBG_CTRL, "allocate dlpbld's mac_list out of memory!!\n")
            return -1;
        }

        for (i = 0; i < dlpbld.num_macs; i++) {
            const char *mac_str = json_string_value(json_array_get(obj, i));
            ether_aton_r(mac_str, &dlpbld.mac_list[i]);
        }
    } else {
        dlpbld.mac_list = NULL;
    }
    //get del workload mac list
    obj = json_object_get(msg, "delmac");
    dlpbld.num_del_macs = json_array_size(obj);
    DEBUG_CTRL("# of delete macs(%d) bld dlp\n", dlpbld.num_del_macs);
    if (dlpbld.num_del_macs > 0) {
        dlpbld.del_mac_list = calloc(sizeof(struct ether_addr), dlpbld.num_del_macs);
        if (!dlpbld.del_mac_list) {
            DEBUG_ERROR(DBG_CTRL, "allocate dlpbld's del_mac_list out of memory!!\n")
            if (dlpbld.mac_list){
                free(dlpbld.mac_list);
            }
            return -1;
        }

        for (i = 0; i < dlpbld.num_del_macs; i++) {
            const char *mac_str = json_string_value(json_array_get(obj, i));
            ether_aton_r(mac_str, &dlpbld.del_mac_list[i]);
        }
    } else {
        dlpbld.del_mac_list = NULL;
    }

    //get dlp rule entries
    obj = json_object_get(msg, "dlp_rules");
    dlpbld.num_dlp_rules = json_array_size(obj);
    DEBUG_CTRL("# of dlp rules(%d) bld dlp\n", dlpbld.num_dlp_rules);
    if (dlpbld.num_dlp_rules) {
        dlpbld.dlp_rule_list = calloc(dlpbld.num_dlp_rules, sizeof(dpi_dlp_rule_entry_t));
        if (!dlpbld.dlp_rule_list) {
            DEBUG_ERROR(DBG_CTRL, "allocate dlpbld's dlp_rule_list out of memory!!\n")
            if (dlpbld.mac_list){
                free(dlpbld.mac_list);
            }
            if (dlpbld.del_mac_list){
                free(dlpbld.del_mac_list);
            }
            return -1;
        }
    } else {
        dlpbld.dlp_rule_list = NULL;
    }

    for (i = 0; i < dlpbld.num_dlp_rules; i ++) {
        rule_obj = json_array_get(obj, i);
        strlcpy(dlpbld.dlp_rule_list[i].rulename, json_string_value(json_object_get(rule_obj, "name")), MAX_DLP_RULE_NAME_LEN);
        dlpbld.dlp_rule_list[i].sigid = json_integer_value(json_object_get(rule_obj, "id"));
        pat_obj = json_object_get(rule_obj, "patterns");
        dlpbld.dlp_rule_list[i].num_dlp_rule_pats = json_array_size(pat_obj);
        if (dlpbld.dlp_rule_list[i].num_dlp_rule_pats) {
            dlpbld.dlp_rule_list[i].dlp_rule_pat_list = calloc(dlpbld.dlp_rule_list[i].num_dlp_rule_pats, sizeof(dpi_dlp_rule_pattern_t));
            if (!dlpbld.dlp_rule_list[i].dlp_rule_pat_list) {
                DEBUG_ERROR(DBG_CTRL, "allocate dlpbld's dlp_rule_list[%d]'s dlp_rule_pat_list out of memory!!\n", i)
                ret = -1;
                goto dlpcleanup;
            }
            for (j = 0; j < dlpbld.dlp_rule_list[i].num_dlp_rule_pats; j ++) {
                strlcpy(dlpbld.dlp_rule_list[i].dlp_rule_pat_list[j].rule_pattern, json_string_value(json_array_get(pat_obj, j)), MAX_DLP_RULE_PATTERN_LEN);
            }
        } else {
            dlpbld.dlp_rule_list[i].dlp_rule_pat_list = NULL;
        }
    }

    dpi_sig_bld(&dlpbld, flag);
dlpcleanup:
    if (dlpbld.mac_list){
        free(dlpbld.mac_list);
    }
    if (dlpbld.del_mac_list){
        free(dlpbld.del_mac_list);
    }
    for (i = 0; i < dlpbld.num_dlp_rules; i ++) {
        if (dlpbld.dlp_rule_list[i].dlp_rule_pat_list){
            free(dlpbld.dlp_rule_list[i].dlp_rule_pat_list);
        }
    }
    if (dlpbld.dlp_rule_list) {
        free(dlpbld.dlp_rule_list);
    }
    return ret;
}

static int dp_ctrl_bld_dlp_update_ep(json_t *msg)
{
    dpi_dlpbld_mac_t dlpbld_mac;
    json_t *oldmac_obj, *addmac_obj, *delmac_obj;
    int i;
    int ret = 0;

    oldmac_obj = json_object_get(msg, "oldmac");
    dlpbld_mac.num_old_macs = json_array_size(oldmac_obj);

    DEBUG_CTRL("# of old macs(%d)\n", dlpbld_mac.num_old_macs);

    if (!dlpbld_mac.num_old_macs) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in bld dlp update ep!!\n");
        return -1;
    }
    dlpbld_mac.old_mac_list = calloc(sizeof(struct ether_addr), dlpbld_mac.num_old_macs);
    if (!dlpbld_mac.old_mac_list) {
        DEBUG_ERROR(DBG_CTRL, "allocate dlpbld_mac's old_mac_list out of memory!!\n")
        return -1;
    }

    for (i = 0; i < dlpbld_mac.num_old_macs; i++) {
        const char *mac_str = json_string_value(json_array_get(oldmac_obj, i));
        ether_aton_r(mac_str, &dlpbld_mac.old_mac_list[i]);
    }
    //get del workload mac list
    delmac_obj = json_object_get(msg, "delmac");
    dlpbld_mac.num_del_macs = json_array_size(delmac_obj);
    DEBUG_CTRL("# of delete macs(%d)\n", dlpbld_mac.num_del_macs);
    if (dlpbld_mac.num_del_macs > 0) {
        dlpbld_mac.del_mac_list = calloc(sizeof(struct ether_addr), dlpbld_mac.num_del_macs);
        if (!dlpbld_mac.del_mac_list) {
            DEBUG_ERROR(DBG_CTRL, "allocate dlpbld's del_mac_list out of memory!!\n")
            free(dlpbld_mac.old_mac_list);
            return -1;
        }

        for (i = 0; i < dlpbld_mac.num_del_macs; i++) {
            const char *mac_str = json_string_value(json_array_get(delmac_obj, i));
            ether_aton_r(mac_str, &dlpbld_mac.del_mac_list[i]);
        }
    } else {
        dlpbld_mac.del_mac_list = NULL;
    }

    //get add workload mac list
    addmac_obj = json_object_get(msg, "addmac");
    dlpbld_mac.num_add_macs = json_array_size(addmac_obj);
    DEBUG_CTRL("# of add macs(%d)\n", dlpbld_mac.num_add_macs);
    if (dlpbld_mac.num_add_macs > 0) {
        dlpbld_mac.add_mac_list = calloc(sizeof(struct ether_addr), dlpbld_mac.num_add_macs);
        if (!dlpbld_mac.add_mac_list) {
            DEBUG_ERROR(DBG_CTRL, "allocate dlpbld's add_mac_list out of memory!!\n")
            free(dlpbld_mac.old_mac_list);
            if (dlpbld_mac.del_mac_list)
            {
                free(dlpbld_mac.del_mac_list);
            }
            return -1;
        }

        for (i = 0; i < dlpbld_mac.num_add_macs; i++) {
            const char *mac_str = json_string_value(json_array_get(addmac_obj, i));
            ether_aton_r(mac_str, &dlpbld_mac.add_mac_list[i]);
        }
    } else {
        dlpbld_mac.add_mac_list = NULL;
    }
    ret = dpi_sig_bld_update_mac(&dlpbld_mac);

    free(dlpbld_mac.old_mac_list);
    if (dlpbld_mac.del_mac_list){
        free(dlpbld_mac.del_mac_list);
    }
    if (dlpbld_mac.add_mac_list){
        free(dlpbld_mac.add_mac_list);
    }
    return ret;
}

//to avoid false positive implicit violation, set g_xff_enabled default to 0
uint8_t g_xff_enabled = 0;

static int dp_ctrl_sys_conf(json_t *msg)
{
    json_t *xff_enabled_obj;
    bool xffenabled = false;

    xff_enabled_obj = json_object_get(msg, "xff_enabled");
    if (xff_enabled_obj != NULL) {
        xffenabled = json_boolean_value(xff_enabled_obj);
    }
    g_xff_enabled = xffenabled ? 1 : 0;

    DEBUG_CTRL("g_xff_enabled=%u\n", g_xff_enabled);

    return 0;
}

uint8_t g_disable_net_policy = 0;

static int dp_ctrl_disable_net_policy(json_t *msg)
{
    json_t *disable_net_policy_obj;
    bool disable_net_policy = false;

    disable_net_policy_obj = json_object_get(msg, "disable_net_policy");
    if (disable_net_policy_obj != NULL) {
        disable_net_policy = json_boolean_value(disable_net_policy_obj);
    }
    g_disable_net_policy = disable_net_policy ? 1 : 0;

    DEBUG_CTRL("g_disable_net_policy=%u\n", g_disable_net_policy);

    return 0;
}

uint8_t g_detect_unmanaged_wl = 0;

static int dp_ctrl_detect_unmanaged_wl(json_t *msg)
{
    json_t *detect_unmanaged_wl_obj;
    bool detect_unmanaged_wl = false;

    detect_unmanaged_wl_obj = json_object_get(msg, "detect_unmanaged_wl");
    if (detect_unmanaged_wl_obj != NULL) {
        detect_unmanaged_wl = json_boolean_value(detect_unmanaged_wl_obj);
    }
    g_detect_unmanaged_wl = detect_unmanaged_wl ? 1 : 0;

    DEBUG_CTRL("g_detect_unmanaged_wl=%u\n", g_detect_unmanaged_wl);

    return 0;
}

uint8_t g_enable_icmp_policy = 0;

static int dp_ctrl_enable_icmp_policy(json_t *msg)
{
    json_t *enable_icmp_policy_obj;
    bool enable_icmp_policy = false;

    enable_icmp_policy_obj = json_object_get(msg, "enable_icmp_policy");
    if (enable_icmp_policy_obj != NULL) {
        enable_icmp_policy = json_boolean_value(enable_icmp_policy_obj);
    }
    g_enable_icmp_policy = enable_icmp_policy ? 1 : 0;

    DEBUG_CTRL("g_enable_icmp_policy=%u\n", g_enable_icmp_policy);

    return 0;
}

#define BUF_SIZE 8192
char ctrl_msg_buf[BUF_SIZE];
static int dp_ctrl_handler(int fd)
{
    socklen_t len;
    int size, ret = 0;

    len = sizeof(struct sockaddr_un);
    size = recvfrom(fd, ctrl_msg_buf, BUF_SIZE - 1, 0, (struct sockaddr *)&g_client_addr, &len);
    ctrl_msg_buf[size] = '\0';

    json_t *root;
    json_error_t error;

    root = json_loads(ctrl_msg_buf, 0, &error);
    if (root == NULL) {
        DEBUG_ERROR(DBG_CTRL, "Invalid json format on line %d: %s\n", error.line, error.text);
        return -1;
    }

    const char *key;
    json_t *msg;

    json_object_foreach(root, key, msg) {
        if (strcmp(key, "ctrl_keep_alive") == 0) {
            ret = dp_ctrl_keep_alive(msg);
            continue;
        }
        char *data = NULL;
        DEBUG_CTRL("\"%s\":%s\n", key, data=json_dumps(msg, JSON_ENSURE_ASCII));
        //data needs to be freed otherwise there is memory leak
        free(data);

        if (strcmp(key, "ctrl_add_srvc_port") == 0) {
            ret = dp_ctrl_add_srvc_port(msg);
        } else if (strcmp(key, "ctrl_del_srvc_port") == 0) {
            ret = dp_ctrl_del_srvc_port(msg);
        } else if (strcmp(key, "ctrl_add_port_pair") == 0) {
            ret = dp_ctrl_add_port_pair(msg);
        } else if (strcmp(key, "ctrl_del_port_pair") == 0) {
            ret = dp_ctrl_del_port_pair(msg);
        } else if (strcmp(key, "ctrl_add_tap_port") == 0) {
            ret = dp_ctrl_add_tap_port(msg);
        } else if (strcmp(key, "ctrl_del_tap_port") == 0) {
            ret = dp_ctrl_del_tap_port(msg);
        } else if (strcmp(key, "ctrl_add_nfq_port") == 0) {
            ret = dp_ctrl_add_nfq_port(msg);
        } else if (strcmp(key, "ctrl_del_nfq_port") == 0) {
            ret = dp_ctrl_del_nfq_port(msg);
        } else if (strcmp(key, "ctrl_add_mac") == 0) {
            ret = dp_ctrl_add_mac(msg);
        } else if (strcmp(key, "ctrl_del_mac") == 0) {
            ret = dp_ctrl_del_mac(msg);
        } else if (strcmp(key, "ctrl_cfg_mac") == 0) {
            ret = dp_ctrl_cfg_mac(msg);
        } else if (strcmp(key, "ctrl_cfg_nbe") == 0) {
            ret = dp_ctrl_cfg_nbe(msg);
        } else if (strcmp(key, "ctrl_refresh_app") == 0) {
            ret = dp_ctrl_refresh_app(msg);
        } else if (strcmp(key, "ctrl_stats_macs") == 0) {
            ret = dp_ctrl_stats_macs(msg);
        } else if (strcmp(key, "ctrl_stats_device") == 0) {
            ret = dp_ctrl_stats_device(msg);
        } else if (strcmp(key, "ctrl_counter_device") == 0) {
            ret = dp_ctrl_counter_device(msg);
        } else if (strcmp(key, "ctrl_count_session") == 0) {
            ret = dp_ctrl_count_session(msg);
        } else if (strcmp(key, "ctrl_list_session") == 0) {
            ret = dp_ctrl_list_session(msg);
        } else if (strcmp(key, "ctrl_clear_session") == 0) {
            ret = dp_ctrl_clear_session(msg);
        } else if (strcmp(key, "ctrl_list_meter") == 0) {
            ret = dp_ctrl_list_meter(msg);
        } else if (strcmp(key, "ctrl_set_debug") == 0) {
            ret = dp_ctrl_set_debug(msg);
        // } else if (strcmp(key, "ctrl_get_debug") == 0) {
        //    ret = dp_ctrl_get_debug(msg);
        } else if (strcmp(key, "ctrl_cfg_policy") == 0) {
            ret = dp_ctrl_cfg_policy(msg);
        } else if (strcmp(key, "ctrl_cfg_del_fqdn") == 0) {
            ret = dp_ctrl_del_fqdn(msg);
        } else if (strcmp(key, "ctrl_cfg_set_fqdn") == 0) {
            ret = dp_ctrl_set_fqdn(msg);
        } else if (strcmp(key, "ctrl_cfg_internal_net") == 0) {
            ret = dp_ctrl_cfg_internal_net(msg, true);
        } else if (strcmp(key, "ctrl_cfg_specip_net") == 0) {
            ret = dp_ctrl_cfg_specialip_net(msg);
        } else if (strcmp(key, "ctrl_cfg_policy_addr") == 0) {
            ret = dp_ctrl_cfg_internal_net(msg, false);
        } else if (strcmp(key, "ctrl_cfg_dlp") == 0) {
            ret = dp_ctrl_cfg_dlp(msg);
        } else if (strcmp(key, "ctrl_cfg_dlpmac") == 0) {
            ret = dp_ctrl_del_dlp(msg);
        } else if (strcmp(key, "ctrl_bld_dlp") == 0) {
            ret = dp_ctrl_bld_dlp(msg);
        } else if (strcmp(key, "ctrl_bld_dlpmac") == 0) {
            ret = dp_ctrl_bld_dlp_update_ep(msg);
        } else if (strcmp(key, "ctrl_sys_conf") == 0) {
            ret = dp_ctrl_sys_conf(msg);
        } else if (strcmp(key, "ctrl_disable_net_policy") == 0) {
            ret = dp_ctrl_disable_net_policy(msg);
        } else if (strcmp(key, "ctrl_detect_unmanaged_wl") == 0) {
            ret = dp_ctrl_detect_unmanaged_wl(msg);
        } else if (strcmp(key, "ctrl_enable_icmp_policy") == 0) {
            ret = dp_ctrl_enable_icmp_policy(msg);
        }
        DEBUG_CTRL("\"%s\" done\n", key);
    }

    json_decref(root);

    return ret;
}

// -- threat log

static void dp_ctrl_consume_threat_log(void)
{
    int thr_id;

    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_thread_data_t *th_data = &g_dp_thread_data[thr_id];

        while (true) {
            uint32_t next = (th_data->log_reader + 1) % MAX_LOG_ENTRIES;
            if (next == th_data->log_writer) {
                break;
            }
            uatomic_set(&th_data->log_reader, next);

            DEBUG_LOGGER("Read at entry=%u\n", th_data->log_reader);

            uint8_t *data = th_data->log_ring[th_data->log_reader];
            dp_ctrl_notify_ctrl(data, LOG_ENTRY_SIZE);
        }
    }
}

int dp_ctrl_threat_log(DPMsgThreatLog *log)
{
    dp_thread_data_t *th_data = &g_dp_thread_data[THREAD_ID];

    if (th_data->log_writer == th_data->log_reader) {
        DEBUG_ERROR(DBG_LOG, "Log ring full!\n");
        return -1;
    }

    uint8_t *dst = &th_data->log_ring[th_data->log_writer][sizeof(DPMsgHdr)];
    memcpy(dst, log, sizeof(*log));

    DEBUG_LOGGER("Wrote at entry=%u\n", th_data->log_writer);

    uint32_t next = (th_data->log_writer + 1) % MAX_LOG_ENTRIES;
    uatomic_set(&th_data->log_writer, next);

    return 0;
}

// -- rate limiter
void dp_rate_limiter_reset(dp_rate_limter_t *rl, uint16_t dur, uint16_t dur_cnt_limit)
{
    memset(rl, 0, sizeof(dp_rate_limter_t));
    rl->dur = dur;
    rl->dur_cnt_limit = dur_cnt_limit;
    rl->start = get_current_time();
}

int dp_rate_limiter_check(dp_rate_limter_t *rl)
{
    uint32_t cur = get_current_time();
    int ret;
    if ((cur - rl->start) > rl->dur) {
        if (rl->cnt > rl->dur_cnt_limit) {
            // change level from error to normal to suppress extensive logs
            DEBUG_LOGGER("rate exceeds - received %u limit %u drop %u\n",
                         rl->cnt, rl->dur_cnt_limit, rl->cnt-rl->dur_cnt_limit);
        }
        rl->start = cur;
        rl->cnt = 0;
    }
    rl->cnt ++;
    if (rl->cnt > rl->dur_cnt_limit) {
        rl->total_drop++;
        ret = -1;
    } else {
        rl->total_pass++;
        ret = 0;
    }
    //DEBUG_LOGGER("cnt %u limit %u pass %u drop %u\n",
    //             rl->cnt, rl->dur_cnt_limit, rl->total_pass, rl->total_drop);
    return ret;
}

int dp_read_conn_stats(conn_stats_t *s, int thr_id)
{
    thr_id = thr_id % MAX_DP_THREADS;

    dp_thread_data_t *th_data = &g_dp_thread_data[thr_id];
    dp_rate_limter_t *rl = &th_data->conn4_rl;

    s->limit_drop = rl->total_drop;
    s->limit_pass = rl->total_pass;
    return 0;
}

// -- connection map

typedef struct conn_node_ {
    struct cds_lfht_node node;
    DPMsgConnect conn;
} conn_node_t;

typedef struct conn4_key_ {
    uint32_t pol_id;
    uint32_t client, server;
    uint16_t port;
    uint16_t application;
    uint8_t ipproto;
    bool ingress;
} conn4_key_t;

static int conn4_match(struct cds_lfht_node *ht_node, const void *key)
{
    conn_node_t *cnode = STRUCT_OF(ht_node, conn_node_t, node);
    DPMsgConnect *conn = &cnode->conn;
    const conn4_key_t *ckey = key;

    return (conn->PolicyId == ckey->pol_id &&
            ip4_get(conn->ClientIP) == ckey->client &&
            ip4_get(conn->ServerIP) == ckey->server &&
            !!FLAGS_TEST(conn->Flags, DPCONN_FLAG_INGRESS) == ckey->ingress &&
            conn->Application == ckey->application &&
            conn->ServerPort == ckey->port && conn->IPProto == ckey->ipproto) ? 1 : 0;
}

static uint32_t conn4_hash(const void *key)
{
    const conn4_key_t *ckey = key;

    return sdbm_hash((uint8_t *)&ckey->client, 4) +
           sdbm_hash((uint8_t *)&ckey->server, 4) + ckey->port + ckey->ingress + ckey->pol_id;
}

int dp_ctrl_traffic_log(DPMsgSession *log)
{
    return sizeof(*log);
}

#define TUNNEL_THRESHOLD 800
int dp_ctrl_connect_report(DPMsgSession *log, DPMonitorMetric *metric, int count_session, int count_violate)
{
    dp_thread_data_t *th_data = &g_dp_thread_data[THREAD_ID];

    // TODO: Only care IPv4 sessions
    if (likely(log->EtherType == ETH_P_IP)) {
        conn4_key_t key;

        DEBUG_LOGGER(DBG_MAC_FORMAT" "DBG_IPV4_FORMAT":%u => "DBG_IPV4_FORMAT":%u"
                     " app=%u policy=%u action=%d sess=%d violate=%d threat=%u severity=%d\n",
                     DBG_MAC_TUPLE(log->EPMAC), DBG_IPV4_TUPLE(log->ClientIP), log->ClientPort,
                     DBG_IPV4_TUPLE(log->ServerIP),log->ServerPort,
                     log->Application, log->PolicyId, log->PolicyAction,
                     count_session, count_violate, log->ThreatID, log->Severity);

        // host: IP is on host subnet
        // unkpeer: IP is not on host or container subnets
        if (FLAGS_TEST(log->Flags, DPSESS_FLAG_INGRESS)) {
            /*
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_EXTERNAL) &&
                log->PolicyAction < DP_POLICY_ACTION_VIOLATE) {
                key.client = 0;
            } else {
                // This is east-west traffic, if it's from containers on our managed host,
                // it will be ignored, because it's counted at the egress container,
                // (in bridge mode, we cannot identify src container by client IP and port);
                // if it's from an unmanaged host, we want to record it.
                key.client = ip4_get(log->ClientIP);
            }
            */
            key.client = ip4_get(log->ClientIP);
            key.server = ip4_get(log->ServerIP);
            key.ingress = true;
        } else {
            /*
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_EXTERNAL) &&
                log->PolicyAction < DP_POLICY_ACTION_VIOLATE) {
                key.server = 0;
            } else {
                key.server = ip4_get(log->ServerIP);
            }
            */
            key.server = ip4_get(log->ServerIP);
            key.client = ip4_get(log->ClientIP);
            key.ingress = false;
        }
        key.port = log->ServerPort;
        key.ipproto = log->IPProto;
        key.pol_id = log->PolicyId;

        // Hold the map pointer for RCU access
        uint32_t idx = th_data->conn4_map_cur;
        rcu_map_t *conn4_map = &th_data->conn4_map[idx];
        uint32_t *cnt = &th_data->conn4_map_cnt[idx];
        dp_rate_limter_t *rl = &th_data->conn4_rl;

        conn_node_t *n = rcu_map_lookup(conn4_map, &key);
        if (n != NULL) {
            DPMsgConnect *conn = &n->conn;
            uint32_t last_seen = get_current_time() - log->Idle;
            conn->Bytes += log->ClientBytes + log->ServerBytes;
            conn->Sessions += count_session;
            conn->Violates += count_violate;

            if (last_seen >= conn->LastSeenAt) {
                conn->PolicyAction = log->PolicyAction;
                conn->PolicyId = log->PolicyId;
                conn->LastSeenAt = last_seen;
            }
            if (log->Severity > conn->Severity) {
                conn->ThreatID = log->ThreatID;
                conn->Severity = log->Severity;
            }
            //check dns tunneling, put clientport to report and check it in agent
            if ((log->ServerPort == 53 || log->Application == DPI_APP_DNS) &&
                    !FLAGS_TEST(log->Flags, DPSESS_FLAG_INGRESS) &&
                    log->IPProto == IPPROTO_UDP &&
                    log->ClientBytes > TUNNEL_THRESHOLD) {
                conn->ClientPort = log->ClientPort;
            }
            if (metric != NULL) {
                conn->EpSessCurIn = metric->EpSessCurIn;
                conn->EpSessIn12 = metric->EpSessIn12;
                conn->EpByteIn12 = metric->EpByteIn12;
            }
        } else if (dp_rate_limiter_check(rl) == 0 && (n = calloc(sizeof(*n), 1)) != NULL) {
            DPMsgConnect *conn = &n->conn;
            mac_cpy(conn->EPMAC, log->EPMAC);
            memcpy(conn->ClientIP, &key.client, 4);
            memcpy(conn->ServerIP, &key.server, 4);
            conn->ServerPort = key.port;
            if ((log->ServerPort == 53 || log->Application == DPI_APP_DNS) &&
                    log->IPProto == IPPROTO_UDP &&
                    log->ClientBytes > TUNNEL_THRESHOLD) {
                conn->ClientPort = log->ClientPort;
            }
            conn->IPProto = key.ipproto;
            conn->EtherType = log->EtherType;
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_INGRESS)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_INGRESS);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_EXTERNAL)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_EXTERNAL);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_XFF)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_XFF);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_SVC_EXTIP)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_SVC_EXTIP);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_MESH_TO_SVR)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_MESH_TO_SVR);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_LINK_LOCAL)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_LINK_LOCAL);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_TMP_OPEN)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_TMP_OPEN);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_UWLIP)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_UWLIP);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_CHK_NBE)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_CHK_NBE);
            }
            if (FLAGS_TEST(log->Flags, DPSESS_FLAG_NBE_SNS)) {
                FLAGS_SET(conn->Flags, DPCONN_FLAG_NBE_SNS);
            }

            conn->FirstSeenAt = conn->LastSeenAt = get_current_time() - log->Idle;
            conn->Bytes = log->ClientBytes + log->ServerBytes;
            conn->Sessions = count_session;
            conn->Violates = count_violate;
            conn->Application = log->Application;
            conn->PolicyAction = log->PolicyAction;
            conn->ThreatID = log->ThreatID;
            conn->Severity = log->Severity;
            conn->PolicyId = log->PolicyId;
            if (metric != NULL) {
                conn->EpSessCurIn = metric->EpSessCurIn;
                conn->EpSessIn12 = metric->EpSessIn12;
                conn->EpByteIn12 = metric->EpByteIn12;
            }
            rcu_map_add(conn4_map, n, &key);
            (*cnt)++;
        }
    } else {
        return 0;
    }

    return sizeof(*log);
}

#define CONNECTS_PER_MSG ((DP_MSG_SIZE - sizeof(DPMsgHdr) - sizeof(DPMsgConnectHdr)) / sizeof(DPMsgConnect))
#define CONNECTS_FIRST_ENTRY (DPMsgConnect *)(g_notify_msg + sizeof(DPMsgHdr) + sizeof(DPMsgConnectHdr))

static void send_connects(int count)
{
    //DEBUG_CTRL("count=%d\n", count);

    DPMsgHdr *hdr = (DPMsgHdr *)g_notify_msg;
    DPMsgConnectHdr *ch = (DPMsgConnectHdr *)(g_notify_msg + sizeof(*hdr));
    uint16_t len = sizeof(*hdr) + sizeof(*ch) + sizeof(DPMsgConnect) * count;

    hdr->Kind = DP_KIND_CONNECTION;
    hdr->Length = htons(len);
    hdr->More = 1;
    ch->Connects = htons(count);
    dp_ctrl_notify_ctrl(g_notify_msg, len);
}

static void netify_connects(DPMsgConnect *conn)
{
    conn->ServerPort = htons(conn->ServerPort);
    conn->ClientPort = htons(conn->ClientPort);
    conn->EtherType = htons(conn->EtherType);
    conn->Flags = htons(conn->Flags);
    conn->Bytes = htonl(conn->Bytes);
    conn->Sessions = htonl(conn->Sessions);
    conn->Violates = htonl(conn->Violates);
    conn->Application = htons(conn->Application);
    conn->FirstSeenAt = htonl(conn->FirstSeenAt);
    conn->LastSeenAt = htonl(conn->LastSeenAt);
    conn->PolicyId = htonl(conn->PolicyId);
    conn->ThreatID = htonl(conn->ThreatID);
    conn->EpSessCurIn = htonl(conn->EpSessCurIn);
    conn->EpSessIn12 = htonl(conn->EpSessIn12);
    conn->EpByteIn12 = htonll(conn->EpByteIn12);
}

static void dp_ctrl_update_connects(void)
{
    int thr_id, count, total;
    DPMsgConnect *conn;

    count = total = 0;
    conn = CONNECTS_FIRST_ENTRY;

    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_thread_data_t *th_data = &g_dp_thread_data[thr_id];

        // switch connection map
        rcu_map_t *conn4_map = &th_data->conn4_map[th_data->conn4_map_cur];
        uint32_t *cnt = &th_data->conn4_map_cnt[th_data->conn4_map_cur];
        if (*cnt == 0) {
            continue;
        }
        uatomic_set(&th_data->conn4_map_cur, 1 - th_data->conn4_map_cur);

        synchronize_rcu();

        struct cds_lfht_node *node;
        RCU_MAP_FOR_EACH(conn4_map, node) {
            conn_node_t *n = STRUCT_OF(node, conn_node_t, node);
    
            memcpy(conn, &n->conn, sizeof(*conn));
            netify_connects(conn);

            // Calculate delta
            n->conn.Bytes = 0;
            n->conn.Sessions = 0;

            conn ++;
            count ++;
            total ++;
            if (unlikely(count == CONNECTS_PER_MSG)) {
                send_connects(count);
                count = 0;
                conn = CONNECTS_FIRST_ENTRY;
            }

            rcu_map_del(conn4_map, n);
            free(n);
        }
        *cnt = 0;
    }

    if (count > 0) {
        send_connects(count);
    }

    if (total > 0) {
        DEBUG_TIMER("Sent %u connect entries\n", total);
    }
}

#define FQDN_IPS_PER_MSG ((DP_MSG_SIZE - sizeof(DPMsgHdr) - sizeof(DPMsgFqdnIpHdr)) / sizeof(DPMsgFqdnIp))

static void dp_ctrl_update_fqdn_ip(void)
{
    //this function is called in ctrl thread, but g_fqdn_hdl is initialized
    //in data thread, no guarantee g_fqdn_hdl is already initialized when ctrl
    //thread reach here during dp start, so we check null value here
    if (g_fqdn_hdl == NULL) {
        return;
    }
    struct cds_lfht_node *name_node;

    // Iterate through fqdn map
    RCU_MAP_FOR_EACH(&g_fqdn_hdl->fqdn_name_map, name_node) {
        fqdn_name_entry_t *name_entry = STRUCT_OF(name_node, fqdn_name_entry_t, node);
        if (!(name_entry->r->flag & FQDN_RECORD_WILDCARD)) {//wildcard only
            continue;
        }
        /*if(name_entry->r->iplist.prev==NULL && name_entry->r->iplist.next==NULL) {
            CDS_INIT_LIST_HEAD(&(name_entry->r->iplist));
            continue;
        }*/
        if (uatomic_cmpxchg(&name_entry->r->record_updated, 1, 0) == 0) {
            continue;
        }

        int ipcnt = 0;

        DPMsgHdr *hdr = (DPMsgHdr *)g_notify_msg;
        DPMsgFqdnIpHdr *fh = (DPMsgFqdnIpHdr *)(g_notify_msg + sizeof(*hdr));
        DPMsgFqdnIp *fqdnips = (DPMsgFqdnIp *)(g_notify_msg + sizeof(*hdr) + sizeof(*fh));

        hdr->Kind = DP_KIND_FQDN_UPDATE;
        strlcpy(fh->FqdnName, name_entry->r->name, DP_POLICY_FQDN_NAME_MAX_LEN);
        if (name_entry->r->vh) {
            FLAGS_SET(fh->Flags, DPFQDN_IP_FLAG_VH);
        }
        // Iterate through all ips
        fqdn_ipv4_item_t *ipv4_itr, *ipv4_next;
        cds_list_for_each_entry_safe(ipv4_itr, ipv4_next, &(name_entry->r->iplist), node) {
            ip4_cpy(fqdnips->FqdnIP, (uint8_t *)&ipv4_itr->ip);
            fqdnips++;
            ipcnt++;
            if (ipcnt == FQDN_IPS_PER_MSG) {
                break;
            }
        }
        uint16_t len = sizeof(*hdr) + sizeof(*fh) + sizeof(DPMsgFqdnIp) * ipcnt;
        hdr->Length = htons(len);
        fh->IpCnt = htons(ipcnt);

        if (name_entry->r->ip_cnt != ipcnt) {
            DEBUG_CTRL("Not all ips are sent. ipcnt=%u sent=%u\n", name_entry->r->ip_cnt, ipcnt);
        }

        //DEBUG_CTRL("name: %s flags=0x%02x ipcnt=%d, len=%u\n", fh->FqdnName, fh->Flags, ipcnt, len);

        dp_ctrl_notify_ctrl(g_notify_msg, len);
    }
}

static void dp_ctrl_update_ip_fqdn_storage(void)
{
    //this function is called in ctrl thread, but th_ip_fqdn_storage_map is initialized
    //in data thread, no guarantee th_ip_fqdn_storage_map is already initialized when ctrl
    //thread reach here during dp start, so we check null value here
    if (th_ip_fqdn_storage_map.map == NULL) {
        return;
    }
    struct cds_lfht_node *ip_fqdn_storage_node;

    // Iterate through fqdn map
    RCU_MAP_FOR_EACH(&th_ip_fqdn_storage_map, ip_fqdn_storage_node) {
        dpi_ip_fqdn_storage_entry_t *entry = STRUCT_OF(ip_fqdn_storage_node, dpi_ip_fqdn_storage_entry_t, node);

        if (uatomic_cmpxchg(&entry->r->record_updated, 1, 0) == 0) {
            continue;
        }

        DPMsgHdr *hdr = (DPMsgHdr *)g_notify_msg;
        DPMsgIpFqdnStorageUpdateHdr *fh = (DPMsgIpFqdnStorageUpdateHdr *)(g_notify_msg + sizeof(*hdr));

        hdr->Kind = DP_KIND_IP_FQDN_STORAGE_UPDATE;
        ip4_cpy(fh->IP, (uint8_t *)&entry->r->ip);
        strlcpy(fh->Name, entry->r->name, DP_POLICY_FQDN_NAME_MAX_LEN);
        uint16_t len = sizeof(*hdr) + sizeof(*fh);
        hdr->Length = htons(len);

        DEBUG_CTRL("update ip-fqdn storage, ip=%x name=%s len=%u\n", fh->IP, fh->Name, len);

        dp_ctrl_notify_ctrl(g_notify_msg, len);
    }
}

void dp_ctrl_release_ip_fqdn_storage(dpi_ip_fqdn_storage_entry_t *entry)
{
    DPMsgHdr *hdr = (DPMsgHdr *)g_notify_msg;
    DPMsgIpFqdnStorageReleaseHdr *fh = (DPMsgIpFqdnStorageReleaseHdr *)(g_notify_msg + sizeof(*hdr));

    hdr->Kind = DP_KIND_IP_FQDN_STORAGE_RELEASE;
    ip4_cpy(fh->IP, (uint8_t *)&entry->r->ip);
    uint16_t len = sizeof(*hdr) + sizeof(*fh);
    hdr->Length = htons(len);

    DEBUG_CTRL("release ip-fqdn storage, ip=%x len=%u\n", fh->IP, len);
    
    dp_ctrl_notify_ctrl(g_notify_msg, len);
}

// -- ctrl loop

void dp_ctrl_init_thread_data(void)
{
    int thr_id, i;

    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        dp_thread_data_t *th_data = &g_dp_thread_data[thr_id];

        // Log ring
        th_data->log_reader = MAX_LOG_ENTRIES - 1;
        for (i = 0; i < MAX_LOG_ENTRIES; i ++) {
            DPMsgHdr *hdr = (DPMsgHdr *)th_data->log_ring[i];
            hdr->Kind = DP_KIND_THREAT_LOG;
            hdr->Length = htons(LOG_ENTRY_SIZE);
        }
        
        // Connection map
        rcu_map_init(&th_data->conn4_map[0], 128, offsetof(conn_node_t, node),
                     conn4_match, conn4_hash);
        rcu_map_init(&th_data->conn4_map[1], 128, offsetof(conn_node_t, node),
                     conn4_match, conn4_hash);
        th_data->conn4_map_cnt[0] = 0;
        th_data->conn4_map_cnt[1] = 0;
        dp_rate_limiter_reset(&th_data->conn4_rl, CONNECT_RL_DUR, CONNECT_RL_CNT);
        uatomic_set(&th_data->conn4_map_cur, 0);
    }
}

void dp_ctrl_loop(void)
{
    int ret, round = 0;
    fd_set read_fds;
    struct timeval timeout;
    struct timespec last, now;

    strlcpy(THREAD_NAME, "cmd", MAX_THREAD_NAME_LEN);

    DEBUG_FUNC_ENTRY(DBG_INIT | DBG_CTRL);

    rcu_register_thread();

    unlink(DP_SERVER_SOCK);
    g_ctrl_fd = make_named_socket(DP_SERVER_SOCK);
    g_ctrl_notify_fd = make_notify_client(CTRL_NOTIFY_SOCK);

    pthread_mutex_init(&g_ctrl_req_lock, NULL);
    pthread_cond_init(&g_ctrl_req_cond, NULL);
    pthread_mutex_init(&g_dlp_ctrl_req_lock, NULL);
    pthread_cond_init(&g_dlp_ctrl_req_cond, NULL);

    clock_gettime(CLOCK_MONOTONIC, &last);
    while (g_running) {
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        FD_ZERO(&read_fds);
        FD_SET(g_ctrl_fd, &read_fds);
        ret = select(g_ctrl_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (ret > 0 && FD_ISSET(g_ctrl_fd, &read_fds)) {
            dp_ctrl_handler(g_ctrl_fd);
        }

        clock_gettime(CLOCK_MONOTONIC, &now);

        if (now.tv_sec - last.tv_sec >= 2) {
            last = now;

            dp_ctrl_update_app(false);
            dp_ctrl_update_fqdn_ip();
            dp_ctrl_consume_threat_log();
            dp_ctrl_update_ip_fqdn_storage();

            // every 6s
            if ((round % 3) == 0) {
                dp_ctrl_update_connects();
            }

            round ++;
        }
    }

    close(g_ctrl_notify_fd);
    close(g_ctrl_fd);
    unlink(DP_SERVER_SOCK);

    rcu_map_destroy(&g_ep_map);

    rcu_unregister_thread();
}

void init_dummy_ep(io_ep_t *ep)
{
    rcu_map_init(&ep->app_map, 4, offsetof(io_app_t, node), ep_app_match, ep_app_hash);
    ep->tap = true;
}

