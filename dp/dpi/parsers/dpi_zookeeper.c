#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

enum {
    ELECT_STATUS_NONE   =  0,
    ELECT_STATUS_INIT     ,
    ELECT_STATUS_FOLLOW   ,
    ELECT_STATUS_CONFIRM  ,
    ELECT_STATUS_INVALID  ,
};

enum {
    FOLLOWER_STATUS_NONE = 0,
    FOLLOWER_STATUS_CLI_REQ,
    FOLLOWER_STATUS_SRV_RES,
    FOLLOWER_STATUS_INVALID,
};

enum {
    UDP_SESSION_NONE = 0,
    UDP_SESSION_START,
};

typedef struct zookeeper_udp_data_ {
    uint8_t  elec_status; 
    uint32_t  xid; 
} zookeeper_udp_data_t;

typedef struct zookeeper_wing_ {
    uint32_t seq;
    uint8_t  cli_cnt_init; //1 to initialized, other no inited
} zookeeper_wing_t;

typedef struct zookeeper_data_ {
    zookeeper_wing_t client, server;
    uint8_t  elec_status; 
    uint8_t  follower_status; 
} zookeeper_data_t;

static bool check_len(uint8_t *ptr, uint32_t len, uint32_t total)
{
    int i;

    if (len == total) {
        return true;
    } else {
        for ( i=len; i < total; i++) {
            if (ptr[i]) return false;
        }
        return true;
    }
}
//refer to zookeeper ver 3.3.6 LeaderElection.java and FastLeaderElection.java
//the server send to its neighbour 8 bytes leader's sid in first package
static bool parse_zk_election(dpi_packet_t *p,uint8_t * ptr,uint32_t len, zookeeper_data_t * dp)
{
    uint32_t pkt_len;
    if (dp->elec_status == ELECT_STATUS_INVALID) {
        return false;
    }
    //check first packet
    if (dp->elec_status == ELECT_STATUS_NONE) {
        if (check_len(ptr, 8, len)) {
            dp->elec_status = ELECT_STATUS_INIT;
            DEBUG_LOG(DBG_PARSER, p, "Zookeeper Election ELECT_STATUS_INIT\n");
            return true;
        } else {
            dp->elec_status = ELECT_STATUS_INVALID;
            DEBUG_LOG(DBG_PARSER, p, "Not Zookeeper Election packet\n");
            return false;
        }
    } else if (dp->elec_status == ELECT_STATUS_INIT) {
        if (check_len(ptr, 32, len)) {
            pkt_len = GET_BIG_INT32(ptr);
            if (pkt_len != 0x1c) {
                DEBUG_LOG(DBG_PARSER, p, "Not Zookeeper Election second packet: %d\n",pkt_len);
                dp->elec_status = ELECT_STATUS_INVALID;
                return false;
            }
            dp->elec_status = ELECT_STATUS_FOLLOW;
            DEBUG_LOG(DBG_PARSER, p, "Zookeeper Election ELECT_STATUS_FOLLOW\n");
            return true;
        } else {
            DEBUG_LOG(DBG_PARSER, p, "Not Zookeeper Election second packet\n");
            dp->elec_status = ELECT_STATUS_INVALID;
            return false;
        }
    } else if (dp->elec_status == ELECT_STATUS_FOLLOW) {
        if (check_len(ptr, 32, len)) {
            pkt_len = GET_BIG_INT32(ptr);
            if (pkt_len != 0x1c) {
                DEBUG_LOG(DBG_PARSER, p, "Not Zookeeper Election second packet: %d\n",pkt_len);
                dp->elec_status = ELECT_STATUS_INVALID;
                return false;
            }
            dp->elec_status = ELECT_STATUS_CONFIRM;
            DEBUG_LOG(DBG_PARSER, p, "Zookeeper Election ELECT_STATUS_CONFIRM\n");
            return true;
        } else {
            DEBUG_LOG(DBG_PARSER, p, "Not Zookeeper Election second packet\n");
            dp->elec_status = ELECT_STATUS_INVALID;
            return false;
        }
    } else {
        dp->elec_status = ELECT_STATUS_INVALID;
        return false;
    }

}
//refer to zookeeper ver 3.3.6 server/quorum/learner.java
//zookeeper follower and leader connection
static bool parse_zk_follower_talk(dpi_packet_t *p,uint8_t * ptr,uint32_t len, bool client, zookeeper_data_t * dp) 
{
    if (dp->follower_status == FOLLOWER_STATUS_INVALID) {
        return false;
    }
    if ((!client && !check_len(ptr, 20, len)) || (client && !check_len(ptr, 28, len))) {
        dp->follower_status = FOLLOWER_STATUS_INVALID;
        DEBUG_LOG(DBG_PARSER, p, "Zookeeper follower len not match: %d\n",len);
        return false;
    }
    uint32_t type  = GET_BIG_INT32(ptr);
    if (client) {
        if ((type != 0x0b) && (type != 0x10)) {
            dp->follower_status = FOLLOWER_STATUS_INVALID;
            DEBUG_LOG(DBG_PARSER, p, "Zookeeper follower client type not match: %d\n",type);
            return false;
        }
    } else {
        if (type != 0x0a) {
            dp->follower_status = FOLLOWER_STATUS_INVALID;
            DEBUG_LOG(DBG_PARSER, p, "Zookeeper follower client type not match: %d\n",type);
            return false;
        }
    }
    ptr += 4;
    //skip xid;
    ptr += 8;

    //get the follower myid len if client
    if (client) {
        uint32_t data_len  = GET_BIG_INT32(ptr);
        ptr += 4;
        if (data_len != 8) {
            dp->follower_status = FOLLOWER_STATUS_INVALID;
            DEBUG_LOG(DBG_PARSER, p, "Zookeeper follower data len not match: %d\n",data_len);
            return false;
        }
        //skip myid data 
        ptr += 8;
    }
    uint32_t pkt_len  = GET_BIG_INT32(ptr);
    if (pkt_len != 0xffffffff) {
        dp->follower_status = FOLLOWER_STATUS_INVALID;
        DEBUG_LOG(DBG_PARSER, p, "Zookeeper follower pkt len not match: %d\n",pkt_len);
        return false;
    }
    if (dp->follower_status == FOLLOWER_STATUS_NONE) {
        dp->follower_status = FOLLOWER_STATUS_CLI_REQ;
    } else if (dp->follower_status == FOLLOWER_STATUS_CLI_REQ) {
        dp->follower_status = FOLLOWER_STATUS_SRV_RES;
    } else {
        dp->follower_status = FOLLOWER_STATUS_INVALID;
        return false;
    }
    DEBUG_LOG(DBG_PARSER, p, "Zookeeper follower talk:%s\n", client ?"follower":"server");
    return true;
}
//check zookeeper client request
//refer to zookeeper ver 3.3.6 proto/ConnectRequest.java ConnectResponse.java
//0: not enough data
//1: match zookeeper data
//-1: not match zookeeper data
static int parse_zk_client_connection(dpi_packet_t *p,uint8_t * ptr,uint32_t len, bool client, zookeeper_wing_t * w)
{
    uint32_t left = len;
    if (w->cli_cnt_init) {
        DEBUG_LOG(DBG_PARSER, p, "Zookeeper client already\n");
        return 1;
    }
    if (left < 4) return 0;
    uint32_t pkt_len = GET_BIG_INT32(ptr);
    ptr += 4; left -=4;
    if ((client && (pkt_len < 44)) || (!client && (pkt_len < 36))) {
        DEBUG_LOG(DBG_PARSER, p, "Not ZooKeeper packet len: %d\n",pkt_len);
        return -1;
    }
    if (left < 4) return 0;
    uint32_t proto_ver = GET_BIG_INT32(ptr);
    ptr += 4; left -=4;
    if (proto_ver != 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not ZooKeeper proto not 0: %d\n",proto_ver);
        return -1;
    }
    if (client) {
        //skip client lastZxidSeen
        ptr += 8; left -=8;
    }
    //skip timeOut
    ptr += 4; left -=4;
    if (left < 8) return 0;
    uint64_t session_id = be64toh(*(uint64_t *)(ptr));
    if (client && session_id != 0 && !p->ep->zookeeper_svr&& !p->ep->zookeeper_clt) {
        DEBUG_LOG(DBG_PARSER, p, "ZooKeeper client session id not 0: %lld\n",session_id);
        return -1;
    }
    //skip passwd
    w->cli_cnt_init = 1;
    return 1;
}
static void zookeeper_tcp_parser(dpi_packet_t *p)
{
    zookeeper_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not zookeeper: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    zookeeper_wing_t *w;
    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        uint32_t shift = u32_distance(dpi_pkt_seq(p), w->seq);
        ptr = dpi_pkt_ptr(p) + shift;
        len = dpi_pkt_len(p) - shift;
    } else {
        dpi_fire_parser(p);
        return;
    }

    bool zk_client = dpi_is_client_pkt(p);
    if (parse_zk_election(p, ptr, len, data)) {
        if (data->elec_status == ELECT_STATUS_CONFIRM) {
            DEBUG_LOG(DBG_PARSER, p, "ZooKeeper Election connection finish\n");
            if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
                p->ep->zookeeper_svr = true;
            } else {
                p->ep->zookeeper_clt = true;
            }
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        }
        dpi_set_asm_seq(p, w->seq+len);
        w->seq = w->seq + len;
    } else if (parse_zk_follower_talk(p, ptr, len, zk_client, data)) {
        if (data->follower_status == FOLLOWER_STATUS_SRV_RES) {
            DEBUG_LOG(DBG_PARSER, p, "ZooKeeper follower connection finish\n");
            if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
                p->ep->zookeeper_svr = true;
            } else {
                p->ep->zookeeper_clt = true;
            }
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        }
        dpi_set_asm_seq(p, w->seq+len);
        w->seq = w->seq + len;
    } else {
        int res = parse_zk_client_connection(p, ptr, len, zk_client, w);
        if (res == 1) {
            if (data->client.cli_cnt_init && data->server.cli_cnt_init) {
                DEBUG_LOG(DBG_PARSER, p, "ZooKeeper client connection finish\n");
                if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
                    p->ep->zookeeper_svr = true;
                } else {
                    p->ep->zookeeper_clt = true;
                }
                dpi_finalize_parser(p);
                dpi_ignore_parser(p);
            }
            dpi_set_asm_seq(p, w->seq+len);
            w->seq = w->seq + len;
        } else if (res == -1) {
            dpi_fire_parser(p);
        } 
    } 
}

static void zookeeper_tcp_midstream(dpi_packet_t *p)
{
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    ptr = dpi_pkt_ptr(p);
    len = dpi_pkt_len(p);

    if (len >= 12) {
        int32_t pkt_len  = GET_BIG_INT32(ptr);
        int32_t xid      = GET_BIG_INT32(ptr+4);
        int32_t opcode   = GET_BIG_INT32(ptr+8);

        if (pkt_len == 8 && xid == -2 && opcode == 11) {
            DEBUG_LOG(DBG_PARSER, p, "Client ping\n");
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            if ((p->session->flags & DPI_SESS_FLAG_INGRESS) && !dpi_is_client_pkt(p)) {
                p->ep->zookeeper_svr = true;
            } else {
                p->ep->zookeeper_clt = true;
            }
            return;
        } else if (pkt_len == 16 && xid == -2) {
            DEBUG_LOG(DBG_PARSER, p, "Server ping\n");
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            if (!(p->session->flags & DPI_SESS_FLAG_INGRESS) && !dpi_is_client_pkt(p)) {
                p->ep->zookeeper_svr = true;
            } else {
                p->ep->zookeeper_clt = true;
            }
            return;
        }
    }
    dpi_fire_parser(p);
}

//refer to zookeeper ver 3.3.6/server/quorum/LeaderElection.java QuorumPeer.java
static void zookeeper_udp_parser(dpi_packet_t *p)
{
    zookeeper_udp_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);
    bool client = dpi_is_client_pkt(p);
    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!client) {
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        dpi_put_parser_data(p, data);
    }
    len = dpi_pkt_len(p);
    ptr = dpi_pkt_ptr(p);

    if ( (client && !check_len(ptr, 4, len)) || (!client && !check_len(ptr, 36, len))) {
        dpi_fire_parser(p);
        return ;
    }
    if (check_len(ptr, 4, len)) {
        data->elec_status = UDP_SESSION_START;
        data->xid         = GET_BIG_INT32(ptr);
        DEBUG_LOG(DBG_PARSER, p, "ZooKeeper election packet, xid: %x\n", data->xid);

    } else if (data->elec_status == UDP_SESSION_START) {
        uint32_t xid = GET_BIG_INT32(ptr);
        if (xid == data->xid) {
            DEBUG_LOG(DBG_PARSER, p, "ZooKeeper election second response packet, xid: %x\n", data->xid);
            if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
                p->ep->zookeeper_svr = true;
            } else {
                p->ep->zookeeper_clt = true;
            }
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        }  else {
            dpi_fire_parser(p);
        }
    } else {
        dpi_fire_parser(p);
    }
}

static void zookeeper_new_session(dpi_packet_t *p)
{
    if (p->session->server.port >= 1024) {
        dpi_hire_parser(p);
    }
}

static void zookeeper_new_mid_sess(dpi_packet_t *p)
{
    if (p->sport >= 1024 && p->sport >= 1024) {
        dpi_hire_parser(p);
    }
}

static void zookeeper_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_zookeeper_tcp = {
    .new_session = zookeeper_new_session,
    .delete_data = zookeeper_delete_data,
    .parser = zookeeper_tcp_parser,
    .new_mid_sess = zookeeper_new_mid_sess,
    .midstream = zookeeper_tcp_midstream,
    .name = "zookeeper",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_ZOOKEEPER,
};

dpi_parser_t *dpi_zookeeper_tcp_parser(void)
{
    return &dpi_parser_zookeeper_tcp;
}

static dpi_parser_t dpi_parser_zookeeper_udp = {
    .new_session = zookeeper_new_session,
    .delete_data = zookeeper_delete_data,
    .parser = zookeeper_udp_parser,
    .name = "zookeeper",
    .ip_proto = IPPROTO_UDP,
    .type = DPI_PARSER_ZOOKEEPER,
};

dpi_parser_t *dpi_zookeeper_udp_parser(void)
{
    return &dpi_parser_zookeeper_udp;
}
