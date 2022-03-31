#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <linux/netfilter/nfnetlink_queue.h>

#include "urcu.h"
#include "urcu/rcuhlist.h"

#include "main.h"
#include "apis.h"
#include "debug.h"
#include "utils/helper.h"

#define NFQ_PKT_SIZE_JUMBO (1024 * 10)
#define NFQ_PKT_SIZE (1024 * 2)
#define MAX_NFQ_BUF_SIZE 65536
static uint8_t g_nfq_rx_buf[MAX_NFQ_BUF_SIZE];
static uint8_t g_rcv_packet[MAX_NFQ_BUF_SIZE];

static int dp_nfq_rx_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                       struct nfq_data *nfa, void *data)
{
	int ret;
    int verdict = 0;
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload_data;
    uint8_t *dpi_rcv_pkt_ptr;
    io_ctx_t context;
    dp_context_t *ctx = (dp_context_t *)data;
    struct ethhdr *nfq_eth;

    context.dp_ctx = ctx;
    context.tick = ctx->nfq_ctx.last_tick;
    context.stats_slot = g_stats_slot;
    context.tap = ctx->tap;
    context.tc = ctx->tc;
    context.nfq = true;
    mac_cpy(context.ep_mac.ether_addr_octet, ctx->ep_mac.ether_addr_octet);
    
    dpi_rcv_pkt_ptr = g_nfq_rx_buf;

    //set up ether header
    nfq_eth = (struct ethhdr *)dpi_rcv_pkt_ptr;
    memset(nfq_eth->h_dest, 0, ETHER_ADDR_LEN);
    memset(nfq_eth->h_source, 0, ETHER_ADDR_LEN);
    nfq_eth->h_proto = htons(ETH_P_IP);

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
        //DEBUG_PACKET("hw_protocol=0x%04x hook=%u id=%u, dp ctx:%s\n", ntohs(ph->hw_protocol), ph->hook, id, ctx->name); 
	}
	ret = nfq_get_payload(nfa, &payload_data);
	if (ret >= 0) {
        int total_len = ret + sizeof(struct ethhdr);
        memcpy(&dpi_rcv_pkt_ptr[sizeof(struct ethhdr)], payload_data, ret);
        verdict = dpi_recv_packet(&context, dpi_rcv_pkt_ptr, total_len);
        if (verdict == 1) {//drop
            nfq_set_verdict(ctx->nfq_ctx.nfq_q_hdl, id, NF_DROP, 0, NULL);
            ctx->nfq_ctx.rx_deny++;
        } else {//accept
            nfq_set_verdict(ctx->nfq_ctx.nfq_q_hdl, id, NF_ACCEPT, 0, NULL);
            ctx->nfq_ctx.rx_accept++;
        }
    }

    return 0;
}

static int dp_rx_nfq(dp_context_t *ctx, uint32_t tick)
{
	int len;
    uint8_t *rcv_pkt_ptr;
    dp_nfq_t *nfq_ctx = &ctx->nfq_ctx;
    uint32_t count = 0;
    nfq_ctx->last_tick = tick;
    size_t rcv_size = MAX_NFQ_BUF_SIZE;
    int flag = MSG_DONTWAIT;

    while (count < nfq_ctx->batch) {
        rcv_pkt_ptr = g_rcv_packet;
        count ++;
        if ((len = recv(ctx->fd, rcv_pkt_ptr, rcv_size, flag)) > 0) {
            if (ctx->nfq_ctx.nfq_q_hdl != NULL) {
                nfq_handle_packet(ctx->nfq_ctx.nfq_hdl, (char *)rcv_pkt_ptr, len);
            }
        }
    }
    return DP_RX_MORE;
}


static void dp_stats_nfq(dp_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->stats.rx += ctx->nfq_ctx.rx_accept;
    ctx->nfq_ctx.rx_accept = 0;
    ctx->stats.rx_drops += ctx->nfq_ctx.rx_deny;
    ctx->nfq_ctx.rx_deny = 0;
}


static int dp_ring_nfq(int fd, struct nfq_handle *nfq_hdl, struct nfq_q_handle *nfq_q_hdl, 
        dp_nfq_t *nfq_ctx, bool jumboframe, uint blocks, uint batch)
{
    int opt;
    nfq_ctx->nfq_hdl = nfq_hdl;
    nfq_ctx->nfq_q_hdl = nfq_q_hdl;
    nfq_ctx->blocks = blocks;
    nfq_ctx->batch = batch;
    nfq_ctx->rx = dp_rx_nfq;
    nfq_ctx->stats = dp_stats_nfq;
    //Don't send error about no buffer space available
    opt = 1;
    if (setsockopt(fd, SOL_NETLINK,
                   NETLINK_NO_ENOBUFS, &opt, sizeof(int)) == -1) {
        DEBUG_ERROR(DBG_CTRL, "can't set netlink enobufs.\n");
    }
#if 0
    //increase queue max length to resist to packets burst
    //set by user, under container ns the buffersize seems not setable
    //leave code here
    if (nfq_ctx->blocks > 0) {
        if (nfq_set_queue_maxlen(nfq_q_hdl, nfq_ctx->blocks) < 0)
        {
            DEBUG_ERROR(DBG_CTRL, "error during nfq_set_queue_maxlen().\n");
        }
        socklen_t buffersize;
        if (jumboframe) {
            buffersize = nfq_ctx->blocks * NFQ_PKT_SIZE_JUMBO; 
        } else {
            buffersize = nfq_ctx->blocks * NFQ_PKT_SIZE; 
        }
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &buffersize, sizeof(socklen_t)) == -1) {
            DEBUG_ERROR(DBG_CTRL, "can't set netlink SO_RCVBUFFORCE\n");
            //if SO_RCVBUFFORCE didn't work, we try at least to get the system
            //wide maximum (or whatever the user requested)
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffersize, sizeof(socklen_t));
        }
    }
#endif
    return 0;
}

int dp_open_nfq_handle(dp_context_t *ctx, bool jumboframe, uint blocks, uint batch)
{
    struct nfq_handle *nfq_hdl;
	struct nfq_q_handle *nfq_q_hdl;
	int fd;
    int err;
	uint32_t nfq_queue_num = 0;

    DEBUG_CTRL("opening nfq handle\n");
	nfq_hdl = nfq_open();
	if (!nfq_hdl) {
        DEBUG_ERROR(DBG_CTRL, "fail to open nfq_hdl\n");
        return -1;
	}

    DEBUG_CTRL("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(nfq_hdl, AF_INET) < 0) {
        DEBUG_ERROR(DBG_CTRL, "error during nfq_unbind_pf()\n");
        return -1;
	}

    DEBUG_CTRL("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(nfq_hdl, AF_INET) < 0) {
        DEBUG_ERROR(DBG_CTRL, "error during nfq_bind_pf()\n");
        return -1;
	}

    DEBUG_CTRL("binding this socket to queue(%d)\n", nfq_queue_num);
	nfq_q_hdl = nfq_create_queue(nfq_hdl, nfq_queue_num, &dp_nfq_rx_cb, (void *)ctx);
	if (!nfq_q_hdl) {
        DEBUG_ERROR(DBG_CTRL, "error during nfq_create_queue()\n");
        return -1;
	}

    DEBUG_CTRL("setting nfq copy_packet mode\n");
	if (nfq_set_mode(nfq_q_hdl, NFQNL_COPY_PACKET, 0xffff) < 0) {
        DEBUG_ERROR(DBG_CTRL, "can't set packet_copy mode\n");
        return -1;
	}

    // NFQA_CFG_F_FAIL_OPEN (requires Linux kernel >= 3.6): the kernel will
    // accept the packets if the kernel queue gets full. If this flag is not
    // set, the default action in this case is to drop packets.
    DEBUG_CTRL("setting flags to fail open\n");
	if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN)) {
        DEBUG_ERROR(DBG_CTRL, "This kernel version does not allow to set fail oepn.\n");
        //return -1;
	}
    // NFQA_CFG_F_GSO (requires Linux kernel >= 3.10): the kernel will
    // not normalize offload packets, i.e. your application will need to
    // be able to handle packets larger than the mtu.
    // Normalization is expensive, so this flag should always be set.
    DEBUG_CTRL("setting flags to gso\n");
	if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO)) {
        DEBUG_ERROR(DBG_CTRL, "This kernel version does not allow to set gso.\n");
        //return -1;
	}

    /*DEBUG_CTRL("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        DEBUG_ERROR(DBG_CTRL, "This kernel version does not allow to retrieve process UID/GID.\n");
        //return -1;
	}

    DEBUG_CTRL("setting flags to request security context\n");
	if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        DEBUG_ERROR(DBG_CTRL, "This kernel version does not allow to retrieve security context.\n");
        //return -1;
	}*/
	fd = nfq_fd(nfq_hdl);
    if (fd < 0) {
        DEBUG_CTRL("fd(%d), dp ctx(%p)\n", fd, ctx);
        return -1;
    }
    err = dp_ring_nfq(fd, nfq_hdl, nfq_q_hdl, &ctx->nfq_ctx, jumboframe, blocks, batch);
    if (err < 0) {
        if (ctx->nfq_ctx.nfq_q_hdl) {
            nfq_destroy_queue(ctx->nfq_ctx.nfq_q_hdl);
            ctx->nfq_ctx.nfq_q_hdl = NULL;
        }
        if (ctx->nfq_ctx.nfq_hdl) {
            nfq_close(ctx->nfq_ctx.nfq_hdl);
            ctx->nfq_ctx.nfq_hdl = NULL;
        }
        return -1;
    }

    return fd;
}
