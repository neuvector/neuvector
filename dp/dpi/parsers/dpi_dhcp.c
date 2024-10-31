#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

typedef struct dhcp_hdr_ {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic[4];
    uint8_t options[0];
} dhcp_hdr_t;

static const uint8_t dhcp_magic[] = {0x63, 0x82, 0x53, 0x63};

static void dhcp_parser(dpi_packet_t *p)
{
    dhcp_hdr_t *dhcp = (dhcp_hdr_t *)dpi_pkt_ptr(p);
    uint32_t len = dpi_pkt_len(p);

    if (len < sizeof(dhcp_hdr_t) + 4 || dhcp->hlen > 16 ||
        memcmp(dhcp->magic, dhcp_magic, sizeof(dhcp_magic)) != 0) {
        dpi_fire_parser(p);
        return;
    }

    dpi_finalize_parser(p);
}

static void dhcp_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static dpi_parser_t dpi_parser_dhcp = {
    .new_session = dhcp_new_session,
    .delete_data = NULL,
    .parser = dhcp_parser,
    .name = "dhcp",
    .ip_proto = IPPROTO_UDP,
    .type = DPI_PARSER_DHCP,
};

dpi_parser_t *dpi_dhcp_parser(void)
{
    return &dpi_parser_dhcp;
}
