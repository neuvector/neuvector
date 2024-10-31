#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

enum {
    SSH_STAGE_BANNER = 0,
    SSH_STAGE_KEY,
};

typedef struct ssh_wing_ {
    uint32_t seq;
    uint8_t stage;
} ssh_wing_t;

typedef struct ssh_data_ {
    ssh_wing_t client, server;
    uint8_t ver;
} ssh_data_t;


// Return offset of end of line; return 0 if more data is needed, -1 if not SSH
static int ssh_banner(dpi_packet_t *p, uint8_t *ptr, uint32_t len)
{
    ssh_data_t *data = dpi_get_parser_data(p);
    uint8_t *end = ptr + len, *eol = ptr, *ver, *space = NULL;

    if (len < 8) return 0;

    if (memcmp(ptr, "SSH-", 4) != 0 || (ptr[4] != '1' && ptr[4] != '2') ||
        ptr[5] != '.' || !isdigit(ptr[6])) {
        return -1;
    }

    ver = ptr + 8;
    while (eol < end) {
        if (*eol == '\r' || *eol == '\n') {
            break;
        } else if (*eol == ' ' && space == NULL) {
            space = eol;
        } else if (!isprint(*eol)) {
            return -1;
        }

        eol ++;
    }

    if (eol == end) return 0;

    DEBUG_LOG(DBG_PARSER, p, "%s version: %c%c%c\n",
              dpi_is_client_pkt(p) ? "Client" : "Server", ptr[4], ptr[5], ptr[6])

    if (!dpi_is_client_pkt(p)) {
        if (space != NULL) {
            dpi_ep_set_server_ver(p, (char *)ver, space - ver);
        } else {
            dpi_ep_set_server_ver(p, (char *)ver, eol - ver);
        }
    }

    // Skip end of line chars.
    while (++ eol < end && (*eol == '\r' || *eol == '\n')) {;}

    if ((eol - ptr) > 7 && ptr[4] == '1' && ptr[6] == '9' && ptr[7] == '9') {
        data->ver = (data->ver == 1) ? 1 : 2;
    } else {
        data->ver = (data->ver == 1) ? 1 : ptr[4] - '0';
    }

    if (data->ver < 2) {
        DEBUG_ERROR(DBG_PARSER, "SSH version 1\n");
        dpi_threat_trigger(DPI_THRT_SSH_VER_1, p, NULL);
    }

    return eol - ptr;
}

static void ssh_parser(dpi_packet_t *p)
{
    ssh_data_t *data;
    ssh_wing_t *w;
    uint8_t *ptr;
    uint32_t len;

    // To accommodate 'nc' to ssh server case, session is marked as SSH if server side
    // traffic follows SSH protocol. Real SSH client will send data first from client
    // side, but in 'nc' case, only server sends. 
    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        // if (!dpi_is_client_pkt(p)) {
        //     DEBUG_LOG(DBG_PARSER, p, "Not SSH: First packet from server\n");
        //     dpi_fire_parser(p);
        //     return;
        // }

        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }

        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        data->client.stage = data->server.stage = SSH_STAGE_BANNER;

        dpi_put_parser_data(p, data);
    } else if (data->client.stage != SSH_STAGE_BANNER &&
               data->server.stage != SSH_STAGE_BANNER) {
        return;
    }

    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);

        int eol = ssh_banner(p, ptr, len);
        switch (eol) {
        case -1:
            dpi_fire_parser(p);
            return;
        case 0:
            return;
        default:
            if (!dpi_is_client_pkt(p)) {
                dpi_finalize_parser(p);
            }

            w->stage = SSH_STAGE_KEY;

            ptr += eol;
            len -= eol;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);

            if (data->server.stage != SSH_STAGE_BANNER) {
                dpi_ignore_parser(p);
            }
            break;
        }
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        uint32_t shift = u32_distance(dpi_pkt_seq(p), w->seq);
        len = dpi_pkt_len(p) - shift;
    } else {
        dpi_fire_parser(p);
        return;
    }

    // No assembly after passing banner stage
    w->seq += len;
    dpi_set_asm_seq(p, w->seq);
}

static void ssh_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void ssh_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_ssh = {
    .new_session = ssh_new_session,
    .delete_data = ssh_delete_data,
    .parser = ssh_parser,
    .name = "ssh",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_SSH,
};

dpi_parser_t *dpi_ssh_parser(void)
{
    return &dpi_parser_ssh;
}

