#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

static void echo_parser(dpi_packet_t *p)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    if (p->sport != 7 && p->dport != 7) {
        dpi_fire_parser(p);
        return;
    }
    dpi_finalize_parser(p);
    dpi_ignore_parser(p);
}

static void echo_new_session(dpi_packet_t *p)
{
    if (p->sport != 7 && p->dport != 7) {
        return;
    }
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);
    dpi_hire_parser(p);
}

static dpi_parser_t dpi_parser_echo_tcp = {
    .new_session = echo_new_session,
    .delete_data = NULL,
    .parser = echo_parser,
    .name = "echo",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_ECHO,
};

dpi_parser_t *dpi_echo_tcp_parser(void)
{
    return &dpi_parser_echo_tcp;
}

static dpi_parser_t dpi_parser_echo_udp = {
    .new_session = echo_new_session,
    .delete_data = NULL,
    .parser = echo_parser,
    .name = "echo",
    .ip_proto = IPPROTO_UDP,
    .type = DPI_PARSER_ECHO,
};

dpi_parser_t *dpi_echo_udp_parser(void)
{
    return &dpi_parser_echo_udp;
}
