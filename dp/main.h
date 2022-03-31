#ifndef __MAIN_H__
#define __MAIN_H__

#include <linux/if_packet.h>
#include <sys/epoll.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "urcu.h"
#include "urcu/hlist.h"

#include "utils/timer_queue.h"
#include "utils/rcu_map.h"

extern int g_running;
extern int g_stats_slot;
extern int g_dp_threads;

typedef struct dp_stats_ {
    uint64_t rx;
    uint64_t rx_drops;
    uint64_t tx_drops;
    uint64_t tx;
} dp_stats_t;

typedef struct conn_stats_ {
    uint64_t limit_drop;
    uint64_t limit_pass;
} conn_stats_t;

typedef struct rate_limiter_ {
    uint16_t dur;             // in second
    uint16_t dur_cnt_limit;
    uint32_t start;
    uint32_t cnt;
    uint32_t total_drop;
    uint32_t total_pass;
} dp_rate_limter_t;

#define DP_RX_DONE 0
#define DP_RX_MORE -1

struct dp_context_;
struct io_ctx_;
typedef struct dp_ring_ {
    uint8_t *rx_map;
    uint8_t *tx_map;
    uint32_t rx_offset;
    uint32_t tx_offset;
    union {
        struct tpacket_req req;
        struct tpacket_req3 req3;
    };
    uint32_t size;
    uint32_t map_size;
    uint32_t batch;
    int (*rx)(struct dp_context_ *ctx, uint32_t tick);
    int (*tx)(struct dp_context_ *ctx, uint8_t *pkt, int len, bool large_frame);
    void (*stats)(int fd, dp_stats_t *stats);
} dp_ring_t;

typedef struct dp_nfq_ {
    struct nfq_handle *nfq_hdl;
    struct nfq_q_handle *nfq_q_hdl;
    uint32_t blocks;//max queue length
    uint32_t batch;
    uint32_t last_tick;
    uint8_t rx_accept;
    uint8_t rx_deny;
    int (*rx)(struct dp_context_ *ctx, uint32_t tick);
    void (*stats)(struct dp_context_ *ctx);
} dp_nfq_t;

typedef struct dp_context_ {
    struct cds_hlist_node link;
    timer_node_t free_node;

    struct epoll_event ee;
    int fd;
#define CTX_NAME_LEN 64 // must be > IFACE_NAME_LEN=16 and "/proc/%d/ns/net"
#define CTX_NFQ_PREFIX "nfq"
    char name[CTX_NAME_LEN];
    dp_ring_t ring;
    dp_nfq_t nfq_ctx;
    dp_stats_t stats;
    struct ether_addr ep_mac;
#define DEFAULT_PENDING_LIMIT 16
    uint8_t tx_pending;
    uint8_t thr_id  :4,
            released:1;
    bool tap;
    bool tc;
    bool jumboframe;
    bool nfq;
    bool epoll;
    struct dp_context_ *peer_ctx; // for vbr peer is self, for no-tc vin/vex pair with each other.
} dp_context_t;

typedef struct dp_bld_dlp_context_ {
    struct epoll_event ee;
    int fd;
} dp_bld_dlp_context_t;

typedef struct dp_thread_data_ {
    int epoll_fd;
    struct cds_hlist_head ctx_list;
    timer_queue_t ctx_free_list;
    struct dp_context_ *ctx_inline;
    pthread_mutex_t ctrl_dp_lock;
    int ctrl_req_evfd;
    uint32_t ctrl_req;
#define MAX_LOG_ENTRIES 128
#define LOG_ENTRY_SIZE (sizeof(DPMsgHdr) + sizeof(DPMsgThreatLog))
    uint32_t log_writer;
    uint32_t log_reader;
    uint8_t log_ring[MAX_LOG_ENTRIES][LOG_ENTRY_SIZE];
    rcu_map_t conn4_map[2];
    uint32_t conn4_map_cnt[2];
    dp_rate_limter_t conn4_rl;
#define CONNECT_RL_DUR  2
#define CONNECT_RL_CNT  400
    uint32_t conn4_map_cur;
} dp_thread_data_t;

extern dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

#endif
