#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include "urcu.h"
#include "urcu/rcuhlist.h"

#include "main.h"
#include "apis.h"
#include "debug.h"
#include "utils/helper.h"

extern dp_context_t *dp_inline_context();

#define MAX_TSO_SIZE 65536
static uint8_t g_tso_packet[MAX_TSO_SIZE];

#define ERR_UNSUPPORT_v3 (-255)

#define FRAME_SIZE_V1 (1024 * 2)
#define BLOCK_SIZE_V1 (FRAME_SIZE_V1 * 4)

#define FRAME_SIZE_JUMBO_V1 (1024 * 16)
#define BLOCK_SIZE_JUMBO_V1 (FRAME_SIZE_JUMBO_V1 * 2)

#define FRAME_SIZE_V3 (1024 * 2)
#define BLOCK_SIZE_V3 (1024 * 64)

static int dp_ring_bind(int fd, const char *iface)
{
    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = if_nametoindex(iface);
    ll.sll_hatype = 0;
    ll.sll_pkttype = 0;
    ll.sll_halen = 0;

    return bind(fd, (struct sockaddr *)&ll, sizeof(ll));
}

static void dp_tx_flush(dp_context_t *ctx, int limit)
{
    //DEBUG_PACKET("pending=%u limit=%u\n", ctx->tx_pending, limit);

    if (ctx->tx_pending >= limit && ctx->tx_pending > 0) {
        send(ctx->fd, NULL, 0, 0);
        ctx->stats.tx += ctx->tx_pending;
        ctx->tx_pending = 0;
    }
}

static int dp_tx_v1(dp_context_t *ctx, uint8_t *pkt, int len, bool large_frame)
{
    //DEBUG_FUNC_ENTRY(DBG_PACKET);

    dp_ring_t *ring = &ctx->ring;
    struct tpacket_hdr *tp;
    int ret = len;

    if (large_frame) {
        dp_tx_flush(ctx, 0);

        ret = send(ctx->fd, pkt, len, 0);
        DEBUG_PACKET("Sent large frame: len=%u to %s\n", len, ctx->name);

        return ret;
    }

    tp = (struct tpacket_hdr *)(ring->tx_map + ring->tx_offset);
    if ((tp->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING)) == 0) {
        uint8_t *data = (uint8_t *)tp + TPACKET_HDRLEN - sizeof(struct sockaddr_ll);

        memcpy(data, pkt, len);
        tp->tp_len = len;

        tp->tp_status = TP_STATUS_SEND_REQUEST;
        ctx->tx_pending ++;

        if (!ctx->tap && ctx->jumboframe) {
            ring->tx_offset = (ring->tx_offset + FRAME_SIZE_JUMBO_V1) & (ring->size - 1);
        } else {
            ring->tx_offset = (ring->tx_offset + FRAME_SIZE_V1) & (ring->size - 1);
        }

        dp_tx_flush(ctx, DEFAULT_PENDING_LIMIT);

        //DEBUG_PACKET("Sent len=%u to %s\n", len, ctx->name);
    } else {
        DEBUG_PACKET("TX queue full, status=0x%x Drop!\n", tp->tp_status);

        ctx->stats.tx_drops ++;
        ret = -1;
    }

    return ret;
}

static int dp_rx_v1(dp_context_t *ctx, uint32_t tick)
{
    io_ctx_t context;
    uint32_t count = 0;
    dp_ring_t *ring = &ctx->ring;

    context.dp_ctx = ctx;
    context.tick = tick;
    context.stats_slot = g_stats_slot;
    context.tap = ctx->tap;
    context.tc = ctx->tc;
    context.nfq = false;
    mac_cpy(context.ep_mac.ether_addr_octet, ctx->ep_mac.ether_addr_octet);

    while (count < ring->batch) {
        struct tpacket_hdr *tp;

        tp = (struct tpacket_hdr *)(ring->rx_map + ring->rx_offset);

        if ((tp->tp_status & TP_STATUS_USER) == 0) {
            if (likely(!ctx->tap)) {
                dp_tx_flush(ctx->peer_ctx, 0);
            }
            return count;
        }

        count ++;

        if (unlikely(tp->tp_len != tp->tp_snaplen)) {
            if (tp->tp_status & TP_STATUS_COPY) {
                if (tp->tp_len <= MAX_TSO_SIZE) {
                    int len = recv(ctx->fd, g_tso_packet, MAX_TSO_SIZE, 0);
                    DEBUG_PACKET("Recv large frame: len=%u from %s\n", len, ctx->name); 

                    context.large_frame = true;
                    dpi_recv_packet(&context, g_tso_packet, len);
                } else {
                    // read to consume
                    recv(ctx->fd, g_tso_packet, 1, 0);

                    DEBUG_PACKET("Discard: len=%u snap=%u from %s\n",
                                 tp->tp_len, tp->tp_snaplen, ctx->name);
                }
            } else {
                DEBUG_PACKET("Discard: len=%u snap=%u from %s\n",
                             tp->tp_len, tp->tp_snaplen, ctx->name);
            }
        } else {
            context.large_frame = false;
            dpi_recv_packet(&context, (uint8_t *)tp + tp->tp_mac, tp->tp_snaplen);
        }

        tp->tp_status = TP_STATUS_KERNEL;
        if (!ctx->tap && ctx->jumboframe) {
            ring->rx_offset = (ring->rx_offset + FRAME_SIZE_JUMBO_V1) & (ring->size - 1);
        } else {
            ring->rx_offset = (ring->rx_offset + FRAME_SIZE_V1) & (ring->size - 1);
        }
    }

    if (likely(!ctx->tap)) {
        dp_tx_flush(ctx->peer_ctx, 0);
    }
    return DP_RX_MORE;
}

static void dp_stats_v1(int fd, dp_stats_t *stats)
{
    struct tpacket_stats s;
    socklen_t len;
    int err;

    len = sizeof(s);
    err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &s, &len);
    if (err < 0) {
        return;
    }

    stats->rx += s.tp_packets;
    stats->rx_drops += s.tp_drops;
}

static int dp_ring_v1(int fd, const char *iface, dp_ring_t *ring, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int enable = 1;
    // Discard malformed packets
    setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));
    // Packet truncated indication
    setsockopt(fd, SOL_PACKET, PACKET_COPY_THRESH, &enable, sizeof(enable));

    struct tpacket_req *req = &ring->req;
    /*
     * Following comments are quoted from 
     * https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
     *
     * Block size needs to be PAGE_SIZE << MAX_ORDER, PAGE_SIZE is 4096 bytes
     *
     * As stated earlier, each block is a contiguous physical region of memory. 
     * These memory regions are allocated with calls to the __get_free_pages() function.
     * As the name indicates, this function allocates pages of memory, and the second 
     * argument is "order" or a power of two number of pages, that is (for PAGE_SIZE == 4096)
     * order=0 ==> 4096 bytes, order=1 ==> 8192 bytes, order=2 ==> 16384 bytes, etc. 
     *
     */
    if (!tap && jumboframe){
        req->tp_block_size = BLOCK_SIZE_JUMBO_V1;
        req->tp_frame_size = FRAME_SIZE_JUMBO_V1;
    } else {
        req->tp_block_size = BLOCK_SIZE_V1;
        req->tp_frame_size = FRAME_SIZE_V1;
    }
    req->tp_block_nr = blocks;
    req->tp_frame_nr = (req->tp_block_size * blocks) / req->tp_frame_size;
    ring->size = req->tp_block_size * blocks;
    if (!tap) {
        ring->map_size = ring->size * 2;
    } else {
        ring->map_size = ring->size;
    }
    ring->batch = batch;

    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));
    if (!tap) {
        setsockopt(fd, SOL_PACKET, PACKET_TX_RING, req, sizeof(*req));
    }

    ring->rx_map = mmap(NULL, ring->map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (ring->rx_map == MAP_FAILED) {
        DEBUG_ERROR(DBG_CTRL, "fail to mmap (size=0x%x).\n", ring->map_size);
        close(fd);
        return -1;
    }

    ring->tx_map = ring->rx_map + ring->size;

    ring->rx = dp_rx_v1;
    ring->tx = dp_tx_v1;
    ring->stats = dp_stats_v1;
    return fd;
}

static int dp_tx_v3(dp_context_t *ctx, uint8_t *pkt, int len, bool large_frame)
{
    return 0;
}

static int dp_rx_v3(dp_context_t *ctx, uint32_t tick)
{
    io_ctx_t context;
    uint32_t count = 0;
    dp_ring_t *ring = &ctx->ring;

    context.dp_ctx = ctx;
    context.tick = tick;
    context.stats_slot = g_stats_slot;
    context.tap = ctx->tap;
    mac_cpy(context.ep_mac.ether_addr_octet, ctx->ep_mac.ether_addr_octet);

    while (count < ring->batch) {
        struct tpacket_block_desc *desc;
        desc = (struct tpacket_block_desc *)(ring->rx_map + ring->rx_offset);
        if ((desc->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            return count;
        }

        if (unlikely(desc->hdr.bh1.block_status & TP_STATUS_COPY)) {
            DEBUG_PACKET("Discard: status=0x%x len=%u from %s\n",
                         desc->hdr.bh1.block_status, desc->hdr.bh1.blk_len, ctx->name);
        } else {
            uint8_t *ptr = (uint8_t *)desc + desc->hdr.bh1.offset_to_first_pkt;
            uint32_t c = desc->hdr.bh1.num_pkts;
            count += c;

            // always consume the whole block
            int i;
            for (i = 0; i < c; i ++) {
                struct tpacket3_hdr *tp = (struct tpacket3_hdr *)ptr;
                dpi_recv_packet(&context, ptr + tp->tp_mac, tp->tp_snaplen);
                ptr += tp->tp_next_offset;
            }
        }

        desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
        ring->rx_offset = (ring->rx_offset + BLOCK_SIZE_V3) & (ring->size - 1);
    }

    return 0;
}

static void dp_stats_v3(int fd, dp_stats_t *stats)
{
    struct tpacket_stats_v3 s;
    socklen_t len;
    int err;

    len = sizeof(s);
    err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &s, &len);
    if (err < 0) {
        return;
    }

    stats->rx += s.tp_packets;
    stats->rx_drops += s.tp_drops;
}

static int dp_ring_v3(int fd, const char *iface, dp_ring_t *ring, bool tap, uint blocks, uint batch)
{
    int val = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val))) {
        DEBUG_ERROR(DBG_CTRL, "fail to set TPACKET_V3.\n");
        return ERR_UNSUPPORT_v3;
    }

    int enable = 1;
    // Discard malformed packets
    setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));
    // Packet truncated indication
    setsockopt(fd, SOL_PACKET, PACKET_COPY_THRESH, &enable, sizeof(enable));

    struct tpacket_req3 *req = &ring->req3;
    req->tp_block_size = BLOCK_SIZE_V3;
    req->tp_frame_size = FRAME_SIZE_V3;
    req->tp_block_nr = blocks;
    req->tp_frame_nr = (req->tp_block_size * blocks) / req->tp_frame_size;
    req->tp_retire_blk_tov = 64;
    req->tp_sizeof_priv = 0;
    req->tp_feature_req_word = 0;
    ring->size = req->tp_block_size * blocks;
    ring->map_size = ring->size;
    ring->batch = batch;

    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));

    ring->rx_map = mmap(NULL, ring->map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (ring->rx_map == MAP_FAILED) {
        DEBUG_ERROR(DBG_CTRL, "fail to mmap (size=0x%x).\n", ring->map_size);
        close(fd);
        return -1;
    }

    ring->rx = dp_rx_v3;
    ring->tx = dp_tx_v3;
    ring->stats = dp_stats_v3;
    return fd;
}

// --

void dp_close_socket(dp_context_t *ctx)
{
    if (ctx->nfq) {
        if (ctx->nfq_ctx.nfq_q_hdl) {
            nfq_destroy_queue(ctx->nfq_ctx.nfq_q_hdl);
            ctx->nfq_ctx.nfq_q_hdl = NULL;
        }
        if (ctx->nfq_ctx.nfq_hdl) {
            nfq_close(ctx->nfq_ctx.nfq_hdl);
            ctx->nfq_ctx.nfq_hdl = NULL;
        }
    } else {
        munmap(ctx->ring.rx_map, ctx->ring.map_size);
        close(ctx->fd);
    }
}

int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to open socket.\n");
        return -1;
    }

    int err = 0;
    //if (tap) {
    if (0) {
        err = dp_ring_v3(fd, iface, &ctx->ring, tap, blocks, batch);
        if (err == ERR_UNSUPPORT_v3) {
            err = dp_ring_v1(fd, iface, &ctx->ring, tap, jumboframe, blocks, batch);
        }
    } else {
        err = dp_ring_v1(fd, iface, &ctx->ring, tap, jumboframe, blocks, batch);
    }
    if (err < 0) {
        close(fd);
        return -1;
    }

    err = dp_ring_bind(fd, iface);
    if (err < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to bind socket.\n");
        dp_close_socket(ctx);
        return -1;
    }

    return fd;
}

int dp_rx(dp_context_t *ctx, uint32_t tick)
{
    if (ctx->nfq) {
        return ctx->nfq_ctx.rx(ctx, tick);
    } else {
        return ctx->ring.rx(ctx, tick);
    }
}

int dp_send_packet(io_ctx_t *context, uint8_t *pkt, int len)
{
    //no send for nfq
    //RST will not be called because session is marked DPI_SESS_FLAG_PROXYMESH
    if (context->nfq) {
        return 0;
    }
    // Example of dp_ctx being NULL is that the session sending out RST after idling time.
    if (unlikely(context->dp_ctx == NULL)) {
        dp_context_t *dp_ctx = dp_inline_context();
        if (unlikely(dp_ctx == NULL)) return -1;

        context->dp_ctx = dp_ctx;
        context->stats_slot = g_stats_slot;
    }

    // Context is released in data path thread too. It's synchronized.
    dp_context_t *ctx = (dp_context_t *)context->dp_ctx;
    ctx = ctx->peer_ctx;
    if (ctx->released) {
        DEBUG_PACKET("Port removed. Drop!\n");

        ctx->stats.tx_drops ++;
        return -1;
    }

    return ctx->ring.tx(ctx, pkt, len, context->large_frame);
}

void dp_get_stats(dp_context_t *ctx)
{
    if (ctx->nfq) {
        ctx->nfq_ctx.stats(ctx);
    } else {
        ctx->ring.stats(ctx->fd, &ctx->stats);
    }
}
