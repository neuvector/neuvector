#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/eventfd.h>

#include "urcu.h"
#include "urcu/rcuhlist.h"

#include "main.h"
#include "apis.h"
#include "debug.h"
#include "utils/helper.h"

extern dp_mnt_shm_t *g_shm;

#define INLINE_BLOCK 2048
#define INLINE_BATCH 4096
#define TAP_BLOCK 512
#define TAP_BATCH 256
#define INLINE_BLOCK_NOTC 512
#define INLINE_BATCH_NOTC 1024
#define NFQ_BLOCK 128//max q length
#define NFQ_BATCH 128
// For a context in free list, usually it can be release when all packets in the queue
// are processed, but there are cases that sessions send out RST after idling some
// time, ctx_inline is used in that case, so we can recycle pretty quickly.
#define RELEASED_CTX_TIMEOUT 5      // 10 second
#define RELEASED_CTX_PRUNE_FREQ 5   // 10 second
#define DP_STATS_FREQ 60            // 1 minute

#define MAX_EPOLL_EVENTS 128

dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

#define th_epoll_fd(thr_id)      (g_dp_thread_data[thr_id].epoll_fd)
#define th_ctx_list(thr_id)      (g_dp_thread_data[thr_id].ctx_list)
#define th_ctx_free_list(thr_id) (g_dp_thread_data[thr_id].ctx_free_list)
#define th_ctx_inline(thr_id)    (g_dp_thread_data[thr_id].ctx_inline)
#define th_ctrl_dp_lock(thr_id)  (g_dp_thread_data[thr_id].ctrl_dp_lock)
#define th_ctrl_req_evfd(thr_id) (g_dp_thread_data[thr_id].ctrl_req_evfd)
#define th_ctrl_req(thr_id)      (g_dp_thread_data[thr_id].ctrl_req)

int bld_dlp_epoll_fd;
int bld_dlp_ctrl_req_evfd;
uint32_t bld_dlp_ctrl_req;

static uint32_t g_seconds;
static time_t g_start_time;

int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool tc, uint blocks, uint batch);
void dp_close_socket(dp_context_t *ctx);
int dp_rx(dp_context_t *ctx, uint32_t tick);
void dp_get_stats(dp_context_t *ctx);
int dp_open_nfq_handle(dp_context_t *ctx, bool jumboframe, uint blocks, uint batch);

dp_context_t *dp_inline_context()
{
    return th_ctx_inline(THREAD_ID);
}

void dp_refresh_stats(struct cds_hlist_head *list)
{
    dp_context_t *ctx;
    struct cds_hlist_node *itr;

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        dp_get_stats(ctx);
    }
}

int dp_read_ring_stats(dp_stats_t *s, int thr_id)
{
    dp_context_t *ctx;
    struct cds_hlist_node *itr;
    struct cds_hlist_head *list;

    thr_id = thr_id % MAX_DP_THREADS;
    list = &th_ctx_list(thr_id);

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        dp_get_stats(ctx);

        s->rx += ctx->stats.rx;
        s->rx_drops += ctx->stats.rx_drops;
        s->tx += ctx->stats.tx;
        s->tx_drops += ctx->stats.tx_drops;
    }

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
    return 0;
}

static dp_context_t *dp_lookup_context(struct cds_hlist_head *list, const char *name)
{
    dp_context_t *ctx;
    struct cds_hlist_node *itr;

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        if (strcmp(ctx->name, name) == 0) {
            return ctx;
        }
    }

    return NULL;
}

static dp_context_t *dp_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int fd;
    dp_context_t *ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    fd = dp_open_socket(ctx, iface, tap, jumboframe, blocks, batch);
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to open dp socket, iface=%s\n", iface);
        free(ctx);
        return NULL;
    }

    ctx->thr_id = thr_id;
    ctx->fd = fd;
    ctx->tap = tap;
    ctx->tc = true;
    ctx->jumboframe = jumboframe;
    ctx->nfq = false;

    DEBUG_CTRL("ctx=%p\n", ctx);

    return ctx;
}

static dp_context_t *dp_alloc_nfq_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int fd;
    dp_context_t *ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    fd = dp_open_nfq_handle(ctx, jumboframe, blocks, batch);
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to open dp nfq handle, iface=%s\n", iface);
        if (ctx && ctx->nfq_ctx.nfq_q_hdl) {
            nfq_destroy_queue(ctx->nfq_ctx.nfq_q_hdl);
            ctx->nfq_ctx.nfq_q_hdl = NULL;
        }
        if (ctx && ctx->nfq_ctx.nfq_hdl) {
            nfq_close(ctx->nfq_ctx.nfq_hdl);
            ctx->nfq_ctx.nfq_hdl = NULL;
        }
        free(ctx);
        return NULL;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    ctx->thr_id = thr_id;
    ctx->fd = fd;
    ctx->tap = tap;
    ctx->tc = true;
    ctx->jumboframe = jumboframe;
    ctx->nfq = true;

    DEBUG_CTRL("nfq ctx=%p\n", ctx);

    return ctx;
}

static int dp_epoll_add_ctx(dp_context_t *ctx, int thr_id)
{
    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;
    if (epoll_ctl(th_epoll_fd(thr_id), EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
        // If the fd already in the epoll, not return error.
        if (errno != EEXIST) {
            DEBUG_ERROR(DBG_CTRL, "fail to add socket to epoll: %s\n", strerror(errno));
            return -1;
        }
    }

    ctx->epoll = true;
    return 0;
}

static int dp_epoll_remove_ctx(dp_context_t *ctx)
{
    if (!ctx->epoll) {
        return 0;
    }

    if (epoll_ctl(th_epoll_fd(ctx->thr_id), EPOLL_CTL_DEL, ctx->fd, &ctx->ee) == -1) {
        // Generate unnecessary error message when dp exits
        // DEBUG_ERROR(DBG_CTRL, "fail to delete socket from epoll: %s\n", strerror(errno));
        return -1;
    }

    ctx->epoll = false;
    return 0;
}

static void dp_remove_context(timer_node_t *node)
{
    dp_context_t *ctx = STRUCT_OF(node, dp_context_t, free_node);
    DEBUG_CTRL("ctx=%s\n", ctx->name);
    dp_close_socket(ctx);
    free(ctx);
}

// Not to release socket memory if 'kill' is false
static void dp_release_context(dp_context_t *ctx, bool kill)
{
    DEBUG_CTRL("ctx=%s fd=%d\n", ctx->name, ctx->fd);

    cds_hlist_del(&ctx->link);
    dp_epoll_remove_ctx(ctx);

    if (kill) {
        dp_close_socket(ctx);
        free(ctx);
    } else {
        DEBUG_CTRL("add context to free list, ctx=%s, ts=%u\n", ctx->name, g_seconds);
        timer_queue_append(&th_ctx_free_list(ctx->thr_id), &ctx->free_node, g_seconds);
        ctx->released = 1;
    }
}

static int enter_netns(const char *netns)
{
    int curfd, netfd;

    if ((curfd = open("/proc/self/ns/net", O_RDONLY)) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to open current network namespace\n");
        return -1;
    }
    if ((netfd = open(netns, O_RDONLY)) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to open network namespace: netns=%s\n", netns);
        close(curfd);
        return -1;
    }
    if (setns(netfd, CLONE_NEWNET) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to enter network namespace: netns=%s error=%s\n", netns, strerror(errno));
        close(netfd);
        close(curfd);
        return -1;
    }
    close(netfd);
    return curfd;
}

static int restore_netns(int fd)
{
    if (setns(fd, CLONE_NEWNET) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to restore network namespace: error=%s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static const char *get_tap_name(char *name, const char *netns, const char *iface)
{
    snprintf(name, CTX_NAME_LEN, "%s-%s", netns, iface);
    return name;
}

int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id)
{
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    if (th_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, netns=%s thr_id=%d\n", netns, thr_id);
        return -1;
    }

    int curns_fd;
    if ((curns_fd = enter_netns(netns)) < 0) {
        return -1;
    }

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    do {
        char name[CTX_NAME_LEN];
        get_tap_name(name, netns, iface);
        ctx = dp_lookup_context(&th_ctx_list(thr_id), name);
        if (ctx != NULL) {
            // handle mac address change
            ether_aton_r(ep_mac, &ctx->ep_mac);
            DEBUG_CTRL("tap already exists, netns=%s iface=%s\n", netns, iface);
            break;
        }

        ctx = dp_alloc_context(iface, thr_id, true, false, TAP_BLOCK, TAP_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;

        if (dp_epoll_add_ctx(ctx, thr_id) < 0) {
            dp_close_socket(ctx);
            free(ctx);
            ret = -1;
            break;
        }

        ether_aton_r(ep_mac, &ctx->ep_mac);
        strlcpy(ctx->name, name, sizeof(ctx->name));
        cds_hlist_add_head_rcu(&ctx->link, &th_ctx_list(thr_id));

        DEBUG_CTRL("tap added netns=%s iface=%s fd=%d\n", netns, iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    restore_netns(curns_fd);

    return ret;
}

int dp_data_del_tap(const char *netns, const char *iface, int thr_id)
{
    int ret = 0;
    dp_context_t *ctx;
 
    thr_id = thr_id % MAX_DP_THREADS;

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    char name[CTX_NAME_LEN];
    get_tap_name(name, netns, iface);
    ctx = dp_lookup_context(&th_ctx_list(thr_id), name);
    if (ctx != NULL) {
        // When switch mode, port is pulled first, normally epoll error happens first.
        // ctx is released at that path.
        dp_release_context(ctx, false);
        DEBUG_CTRL("removed netns=%s iface=%s\n", netns, iface);
    } else {
        ret = -1;
        DEBUG_CTRL("tap cannot be found, netns=%s iface=%s\n", netns, iface);
    }

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    return ret;
}

static const char *get_nfq_name(char *name, const char *netns, const char *iface)
{
    snprintf(name, CTX_NAME_LEN, "%s-%s-%s", CTX_NFQ_PREFIX, netns, iface);
    return name;
}

int dp_data_add_nfq(const char *netns, const char *iface, const char *ep_mac, bool jumboframe, int thr_id)
{
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    if (th_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, netns=%s thr_id=%d\n", netns, thr_id);
        return -1;
    }

    int curns_fd;
    if ((curns_fd = enter_netns(netns)) < 0) {
        return -1;
    }

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    do {
        char name[CTX_NAME_LEN];
        get_nfq_name(name, netns, iface);
        ctx = dp_lookup_context(&th_ctx_list(thr_id), name);
        if (ctx != NULL) {
            // handle mac address change
            ether_aton_r(ep_mac, &ctx->ep_mac);
            DEBUG_CTRL("nfq i/f already exists, netns=%s iface=%s\n", netns, iface);
            break;
        }

        ctx = dp_alloc_nfq_context(iface, thr_id, false, jumboframe, NFQ_BLOCK, NFQ_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;

        if (dp_epoll_add_ctx(ctx, thr_id) < 0) {
            dp_close_socket(ctx);
            free(ctx);
            ret = -1;
            break;
        }

        ether_aton_r(ep_mac, &ctx->ep_mac);
        strlcpy(ctx->name, name, sizeof(ctx->name));
        cds_hlist_add_head_rcu(&ctx->link, &th_ctx_list(thr_id));

        DEBUG_CTRL("nfq added netns=%s iface=%s fd=%d\n", netns, iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    restore_netns(curns_fd);

    return ret;
}

int dp_data_del_nfq(const char *netns, const char *iface, int thr_id)
{
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    char name[CTX_NAME_LEN];
    get_nfq_name(name, netns, iface);
    ctx = dp_lookup_context(&th_ctx_list(thr_id), name);
    if (ctx != NULL) {
        // When switch mode, nfq is not immediately closed.
        // ctx is set to released.
        dp_release_context(ctx, false);
        DEBUG_CTRL("removed nfq netns=%s iface=%s\n", netns, iface);
    } else {
        ret = -1;
        DEBUG_CTRL("nfq cannot be found, netns=%s iface=%s\n", netns, iface);
    }

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    return ret;
}

int dp_data_add_port(const char *iface, bool jumboframe, int thr_id)
{
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    if (th_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, iface=%s thr_id=%d\n", iface, thr_id);
        return -1;
    }

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    do {
        if (th_ctx_inline(thr_id) != NULL) {
            DEBUG_CTRL("iface already exists, iface=%s\n", iface);
            break;
        }

        ctx = dp_alloc_context(iface, thr_id, false, jumboframe, INLINE_BLOCK, INLINE_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;
        th_ctx_inline(thr_id) = ctx;

        strlcpy(ctx->name, iface, sizeof(ctx->name));
        cds_hlist_add_head_rcu(&ctx->link, &th_ctx_list(thr_id));

        DEBUG_CTRL("added iface=%s fd=%d\n", iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    return ret;
}

int dp_data_del_port(const char *iface, int thr_id)
{
    int ret = 0;
    dp_context_t *ctx;
 
    thr_id = thr_id % MAX_DP_THREADS;

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
    ctx = th_ctx_inline(thr_id);
    if (ctx != NULL) {
        // Assume only one non-tap port
        th_ctx_inline(thr_id) = NULL;
        dp_release_context(ctx, false);
        DEBUG_CTRL("removed %s\n", iface);
    } else {
        ret = -1;
        DEBUG_CTRL("iface cannot be found, iface=%s thr_id=%d\n", iface, thr_id);
    }
    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    return ret;
}

int dp_data_add_port_pair(const char *vin_iface, const char *vex_iface, const char *ep_mac, int thr_id) {
    int ret = 0;
    thr_id = thr_id % MAX_DP_THREADS;
    dp_context_t *ctx_in = NULL; 
    dp_context_t *ctx_ex = NULL; 
    
    if (th_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, iface=%s and iface=%s thr_id=%d\n", vin_iface,vex_iface, thr_id);
        return -1;
    }

   
    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    // if context already exist, just use it. On error release all alloc resource
    ctx_in = dp_lookup_context(&th_ctx_list(thr_id), vin_iface);
    if (ctx_in == NULL) {
        ctx_in = dp_alloc_context(vin_iface, thr_id, false, false, INLINE_BLOCK_NOTC, INLINE_BATCH_NOTC);   
        if (ctx_in == NULL) {
            DEBUG_ERROR(DBG_CTRL, "fail to alloc dp_context for %s\n", vin_iface);
            goto error;
        }
        strlcpy(ctx_in->name, vin_iface, sizeof(ctx_in->name));
        ether_aton_r(ep_mac, &ctx_in->ep_mac);
        ctx_in->tc = false;
    } 
    
    ctx_ex = dp_lookup_context(&th_ctx_list(thr_id), vex_iface);
    if (ctx_ex == NULL) {
        ctx_ex = dp_alloc_context(vex_iface, thr_id, false, false, INLINE_BLOCK_NOTC, INLINE_BATCH_NOTC);   
        if (ctx_ex == NULL) {
            DEBUG_ERROR(DBG_CTRL, "fail to alloc dp_context for %s , free context for %s\n", vex_iface, vin_iface);
            goto error;
        } 
        strlcpy(ctx_ex->name, vex_iface, sizeof(ctx_ex->name));
        ether_aton_r(ep_mac, &ctx_ex->ep_mac);
        ctx_ex->tc = false;
    } 

    ctx_in->peer_ctx = ctx_ex;
    ctx_ex->peer_ctx = ctx_in;
  
    if (dp_epoll_add_ctx(ctx_in, thr_id) < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail add epoll for ctx_in for %s\n",vin_iface);
        goto error;
    }

    if (dp_epoll_add_ctx(ctx_ex, thr_id) < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail add epoll for ctx_ex for %s\n",vex_iface);
        goto error;
    }

    // All resouce allocated, add to list and map, link them 
    cds_hlist_add_head_rcu(&ctx_in->link, &th_ctx_list(thr_id));
    cds_hlist_add_head_rcu(&ctx_ex->link, &th_ctx_list(thr_id));

    DEBUG_CTRL("dp_data_add_port_pair added iface=%s fd=%d\n", vin_iface, ctx_in->fd);
    DEBUG_CTRL("dp_data_add_port_pair added iface=%s fd=%d\n", vex_iface, ctx_ex->fd);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
    return ret; 
error:
    if(ctx_in) {
        dp_close_socket(ctx_in);
        free(ctx_in);    
    }
    if(ctx_ex) {
        dp_close_socket(ctx_ex);
        free(ctx_ex);    
    }
    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
    return -1;
}

int dp_data_del_port_pair(const char *vin_iface, const char *vex_iface, int thr_id) {
 
    int ret = 0;
    dp_context_t *ctx;
 
    thr_id = thr_id % MAX_DP_THREADS;

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
    // the ctx since the vex intf move back to container, so the dp thread may already do the release
    ctx = dp_lookup_context(&th_ctx_list(thr_id), vin_iface);
    if (ctx != NULL) {
        dp_release_context(ctx, false);
        DEBUG_CTRL("removed iface=%s\n",vin_iface);
    } else {
        ret = -1;    
        DEBUG_CTRL("iface cannot be found, iface=%s thr_id=%d\n", vin_iface, thr_id);
    }
    
    ctx = dp_lookup_context(&th_ctx_list(thr_id), vex_iface);
    if (ctx != NULL) {
        dp_release_context(ctx, false);
        DEBUG_CTRL("removed iface=%s\n",vex_iface);
    } else {
        ret = -1;    
        DEBUG_CTRL("iface cannot be found, iface=%s thr_id=%d\n", vex_iface, thr_id);
    }
 
    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    return ret;
}


/* This function can only be called by dp_data_wait_ctrl_req_thr() */
static int dp_ctrl_wait_dp_threads(int threads)
{
    int rc, done = 0;

    while (1) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += CTRL_REQ_TIMEOUT;

        rc = pthread_cond_timedwait(&g_ctrl_req_cond, &g_ctrl_req_lock, &ts);
        if (rc == 0) {
            if (++ done == threads) break;
        }
        if (rc == ETIMEDOUT) {
            DEBUG_CTRL("timeout: wait=%d done=%d\n", threads, done);
            break;
        }
    }

    return rc;
}

int dp_data_wait_ctrl_req_thr(int req, int thr_id)
{
    uint64_t w = 1;
    ssize_t s;
    int rc = 0;

    DEBUG_CTRL("req=%d thread=%d\n", req, thr_id);

    pthread_mutex_lock(&g_ctrl_req_lock);
    th_ctrl_req(thr_id) = req;
    s  = write(th_ctrl_req_evfd(thr_id), &w, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        pthread_mutex_unlock(&g_ctrl_req_lock);
        return -1;
    }
    rc = dp_ctrl_wait_dp_threads(1);
    th_ctrl_req(thr_id) = 0;
    pthread_mutex_unlock(&g_ctrl_req_lock);
    return rc;
}

/* This function can only be called by dp_dlp_wait_ctrl_req_thr() */
static int dp_ctrl_wait_dlp_threads()
{
    int rc = 0;

    while (1) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += CTRL_DLP_REQ_TIMEOUT;

        rc = pthread_cond_timedwait(&g_dlp_ctrl_req_cond, &g_dlp_ctrl_req_lock, &ts);
        if (rc == 0) {
            break;
        }
        if (rc == ETIMEDOUT) {
            DEBUG_CTRL("timeout: wait dlp thread\n");
            break;
        }
    }

    return rc;
}

int dp_dlp_wait_ctrl_req_thr(int req)
{
    uint64_t w = 1;
    ssize_t s;
    int rc = 0;

    DEBUG_CTRL("dlp req=%d\n", req);

    pthread_mutex_lock(&g_dlp_ctrl_req_lock);
    bld_dlp_ctrl_req = req;
    s  = write(bld_dlp_ctrl_req_evfd, &w, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        pthread_mutex_unlock(&g_dlp_ctrl_req_lock);
        return -1;
    }
    rc = dp_ctrl_wait_dlp_threads();
    bld_dlp_ctrl_req = 0;
    pthread_mutex_unlock(&g_dlp_ctrl_req_lock);
    return rc;
}


#if 0
void dp_data_set_ctrl_req(int req)
{
    int thr_id;
    uint64_t w = req;

    for (thr_id = 0; thr_id < g_dp_threads; thr_id ++) {
        ssize_t s = write(th_ctrl_req_evfd(thr_id), &w, sizeof(uint64_t));
        if (s != sizeof(uint64_t)) {
        }
    }
}
#endif

static dp_context_t *dp_add_ctrl_req_event(int thr_id)
{
    int fd;
    dp_context_t *ctx;

    DEBUG_FUNC_ENTRY(DBG_CTRL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    fd = eventfd(0, 0);
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to create dp_ctrl_req event fd.\n");
        free(ctx);
        return NULL;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    ctx->thr_id = thr_id;
    ctx->fd = fd;

    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;

    if (epoll_ctl(th_epoll_fd(thr_id), EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
        DEBUG_ERROR(DBG_CTRL, "fail to add socket to epoll: %s\n", strerror(errno));
        close(fd);
        free(ctx);
        return NULL;
    }

    th_ctrl_req_evfd(thr_id) = fd;

    return ctx;
}

static dp_bld_dlp_context_t *dp_add_dlp_ctrl_req_event()
{
    int fd;
    dp_bld_dlp_context_t *ctx;

    DEBUG_FUNC_ENTRY(DBG_CTRL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    fd = eventfd(0, 0);
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to create dp_dlp_ctrl_req event fd.\n");
        free(ctx);
        return NULL;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    ctx->fd = fd;

    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;

    if (epoll_ctl(bld_dlp_epoll_fd, EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
        DEBUG_ERROR(DBG_CTRL, "fail to add bld_dlp socket to epoll: %s\n", strerror(errno));
        close(fd);
        free(ctx);
        return NULL;
    }

    bld_dlp_ctrl_req_evfd = fd;

    return ctx;
}

static inline struct timespec ts_diff(struct timespec s, struct timespec e)
{
    struct timespec d;
    if (e.tv_nsec < s.tv_nsec) {
        d.tv_sec = e.tv_sec - s.tv_sec - 1;
        d.tv_nsec = 1000000000 + e.tv_nsec - s.tv_nsec;
    } else {
        d.tv_sec = e.tv_sec - s.tv_sec;
        d.tv_nsec = e.tv_nsec - s.tv_nsec;
    }
    return d;
}

void *dp_data_thr(void *args)
{
    struct epoll_event epoll_evs[MAX_EPOLL_EVENTS];
    uint32_t tmo;
    int thr_id = *(int *)args;
    dp_context_t *ctrl_req_ev_ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    THREAD_ID = thr_id;
    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "dp%u", thr_id);

    // Create epoll, add ctrl_req event
    if ((th_epoll_fd(thr_id) = epoll_create(MAX_EPOLL_EVENTS)) < 0) {
        DEBUG_INIT("failed to create epoll, thr_id=%u\n", thr_id);
        return NULL;
    }

    ctrl_req_ev_ctx = dp_add_ctrl_req_event(thr_id);
    if (ctrl_req_ev_ctx == NULL) {
        return NULL;
    }

    rcu_register_thread();

    g_shm->dp_active[thr_id] = true;

    pthread_mutex_init(&th_ctrl_dp_lock(thr_id), NULL);
    CDS_INIT_HLIST_HEAD(&th_ctx_list(thr_id));
    timer_queue_init(&th_ctx_free_list(thr_id), RELEASED_CTX_TIMEOUT);

    // Per-thread init
    dpi_init(DPI_INIT);

    DEBUG_INIT("dp thread starts\n");

#define NO_WAIT    0
#define SHORT_WAIT 2
#define LONG_WAIT  1000
    // Even at packet rate of 1M pps, wait 0.002s means 2K packets. DP queue should
    // be able to accomodate it. Increase wait duration reduce idle CPU usage, but
    // worsen the latency, such as ping latency in protect mode.
    tmo = SHORT_WAIT;
    uint32_t last_seconds = g_seconds;
    while (g_running) {
        // Check if polling context exist, if yes, keep polling it.
        dp_context_t *polling_ctx = th_ctx_inline(thr_id);
        if (likely(polling_ctx != NULL)) {
            if (likely(dp_rx(polling_ctx, g_seconds) == DP_RX_MORE)) {
                // If there are more packets to consume, not to add polling context to epoll,
                // use no-wait time out so we can get back to polling right away.
                tmo = NO_WAIT;
                polling_ctx = NULL;
            } else {
                // If all packets are consumed, add polling context to epoll, so once there is
                // a packet, it can be handled.
                if (dp_epoll_add_ctx(polling_ctx, thr_id) < 0) {
                    tmo = SHORT_WAIT;
                    polling_ctx = NULL;
                } else {
                    tmo = LONG_WAIT;
                }
            }
        }

        int i, evs;
        evs = epoll_wait(th_epoll_fd(thr_id), epoll_evs, MAX_EPOLL_EVENTS, tmo);
        if (evs > 0) {
            for (i = 0; i < evs; i ++) {
                struct epoll_event *ee = &epoll_evs[i];
                dp_context_t *ctx = ee->data.ptr;

                if ((ee->events & EPOLLHUP) || (ee->events & EPOLLERR)) {
                    // When switch mode, port is pulled first, then epoll error happens first.
                    // ctx is more likely to be released here
                    DEBUG_ERROR(DBG_CTRL, "epoll error: %s\n", ctx->name);

                    if (ctx != polling_ctx) {
                        pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
                        if (dp_lookup_context(&th_ctx_list(thr_id), ctx->name)) {
                            dp_release_context(ctx, false);
                        }
                        pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
                    }
                } else if (ee->events & EPOLLIN) {
                    if (ctx->fd == th_ctrl_req_evfd(thr_id)) {
                        uint64_t cnt;
                        read(ctx->fd, &cnt, sizeof(uint64_t));
                        if (th_ctrl_req(thr_id)) {
                            io_ctx_t context;
                            context.tick = g_seconds;
                            context.tap = ctx->tap;
                            dpi_handle_ctrl_req(th_ctrl_req(thr_id), &context);
                        }
                    } else {
                        dp_rx(ctx, g_seconds);
                    }
                }
            }
        }

        if (polling_ctx != NULL) {
            dp_epoll_remove_ctx(polling_ctx);
        }

        if (unlikely(g_seconds - last_seconds >= 1)) {
            // Only one thread update the global variable
            if (thr_id == 0) {
                static int stats_tick = 0;
                if (++ stats_tick >= STATS_INTERVAL) {
                    g_stats_slot ++;
                    stats_tick = 0;
                }
            }

            static int ctx_tick = 0;
            if (++ ctx_tick >= RELEASED_CTX_PRUNE_FREQ) {
                timer_queue_trim(&th_ctx_free_list(thr_id), g_seconds, dp_remove_context);
                ctx_tick = 0;
            }

            static int stats_tick = 0;
            if (++ stats_tick >= DP_STATS_FREQ) {
                pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
                dp_refresh_stats(&th_ctx_list(thr_id));
                pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
                stats_tick = 0;
            }

            dpi_timeout(g_seconds);

            // Update heartbeat
            g_shm->dp_hb[thr_id] ++;

            last_seconds = g_seconds;
        }
    }

    close(th_epoll_fd(thr_id));
    th_epoll_fd(thr_id) = 0;

    DEBUG_INIT("dp thread exits\n");

    struct cds_hlist_node *itr, *next;
    dp_context_t *ctx;
    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
    cds_hlist_for_each_entry_safe(ctx, itr, next, &th_ctx_list(thr_id), link) {
        dp_release_context(ctx, true);
    }
    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    close(ctrl_req_ev_ctx->fd);
    free(ctrl_req_ev_ctx);

    rcu_unregister_thread();

    return NULL;
}

void *dp_bld_dlp_thr(void *args)
{
    struct epoll_event epoll_evs[MAX_EPOLL_EVENTS];
    uint32_t tmo;
    dp_bld_dlp_context_t *ctrl_dlp_req_ev_ctx;

    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "dlp");

    // Create epoll, add ctrl_req event
    if ((bld_dlp_epoll_fd = epoll_create(MAX_EPOLL_EVENTS)) < 0) {
        DEBUG_INIT("failed to create epoll, bld_dlp_thr\n");
        return NULL;
    }

    ctrl_dlp_req_ev_ctx = dp_add_dlp_ctrl_req_event();
    if (ctrl_dlp_req_ev_ctx == NULL) {
        return NULL;
    }

    DEBUG_INIT("dp bld_dlp thread starts\n");

#define BLD_DLP_SHORT_WAIT 2
    tmo = BLD_DLP_SHORT_WAIT;
    while (g_running) {
        int i, evs;
        evs = epoll_wait(bld_dlp_epoll_fd, epoll_evs, MAX_EPOLL_EVENTS, tmo);
        if (evs > 0) {
            for (i = 0; i < evs; i ++) {
                struct epoll_event *ee = &epoll_evs[i];
                dp_bld_dlp_context_t *ctx = ee->data.ptr;

                if (ee->events & EPOLLIN) {
                    if (ctx->fd == bld_dlp_ctrl_req_evfd) {
                        uint64_t cnt;
                        read(ctx->fd, &cnt, sizeof(uint64_t));
                        if (bld_dlp_ctrl_req) {
                            dpi_handle_dlp_ctrl_req(bld_dlp_ctrl_req);
                        }
                    }
                }
            }
        }
    }

    close(bld_dlp_epoll_fd);
    bld_dlp_epoll_fd = 0;

    close(ctrl_dlp_req_ev_ctx->fd);
    free(ctrl_dlp_req_ev_ctx);

    return NULL;
    DEBUG_INIT("dp bld_dlp thread exits\n");
}

void *dp_timer_thr(void *args)
{
    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "tmr");
    g_start_time = time(NULL);
    while (g_running) {
        sleep(1);
        g_seconds ++;
        if ((g_seconds & 0x1f) == 0) {
            time_t time_elapsed = time(NULL) - g_start_time;
            if (time_elapsed > g_seconds) {
                DEBUG_TIMER("Advance timer for %us\n", time_elapsed - g_seconds);
                g_seconds = time_elapsed;
            }
        }
    }
    return NULL;
}

time_t get_current_time()
{
    return (g_start_time + g_seconds);
}
