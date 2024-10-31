#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

static bool check_ref_name(uint8_t * ptr)
{
    int i;
    bool end = false;
    for (i=0; i < 4; i++) {
        if (ptr[i] == 0) {
            end = true; 
        } else if (!end && isalpha(ptr[i])) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static void ntp_udp_parser(dpi_packet_t *p)
{
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    len = dpi_pkt_len(p);
    ptr = dpi_pkt_ptr(p);

    if (((p->sport != 123) && (p->dport != 123)) || len < 48) {
        dpi_fire_parser(p);
        return ;
    }
    uint8_t flag  = ptr[0];
    uint8_t ver   = (flag & 0x38) >> 3;
    uint8_t stratum = ptr[1];

    //current ver <= 4
    if (ver > 4) {
        dpi_fire_parser(p);
        return ;
    }

    ptr += 12;
    if (stratum == 1) {
        //reference ID is ascii 
        if (!check_ref_name(ptr)) {
            dpi_fire_parser(p);
            return ;
        } 
    } else if (stratum > 16) {
        dpi_fire_parser(p);
        return ;
    }
    ptr += 4;
    uint32_t ref_time_sec = ntohl(*(uint32_t *)(ptr));
    uint32_t org_time_sec = ntohl(*(uint32_t *)(ptr+8));
    uint32_t rev_time_sec = ntohl(*(uint32_t *)(ptr+16));
    uint32_t trs_time_sec = ntohl(*(uint32_t *)(ptr+24));

    if (ref_time_sec > trs_time_sec || org_time_sec > rev_time_sec) {
        dpi_fire_parser(p);
        return ;
    }
    dpi_finalize_parser(p);
    dpi_ignore_parser(p);
}

static void ntp_new_session(dpi_packet_t *p)
{
    if ((p->sport != 123) && (p->dport != 123)) {
        return ;
    }
    dpi_hire_parser(p);
}

static dpi_parser_t dpi_parser_ntp_udp = {
    .new_session = ntp_new_session,
    .delete_data = NULL,
    .parser = ntp_udp_parser,
    .name = "ntp",
    .ip_proto = IPPROTO_UDP,
    .type = DPI_PARSER_NTP,
};

dpi_parser_t *dpi_ntp_udp_parser(void)
{
    return &dpi_parser_ntp_udp;
}
