#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define TFTP_RRQ        1
#define TFTP_WRQ        2
#define TFTP_DATA       3
#define TFTP_ACK        4
#define TFTP_ERROR      5
#define TFTP_OACK       6
#define TFTP_INFO     255

static bool is_path_name(uint8_t c)
{
    return isdigit(c) || c == '-' || c == '.' || c == '/' || c == '\\' || c == '_' || isalpha(c) ;
}

//return file name len
//-1: invalid
static int check_file_name(uint8_t * ptr, uint16_t len )
{
    int left = len > 128  ? 128: len;
    uint8_t * ptr_end = ptr + left;
    int name_len =0 ;

    while ( ptr < ptr_end) {
        if (*ptr == 0 && name_len > 0) {
            return name_len+1;
        } else if (!is_path_name(*ptr)) {
                return -1 ;
        }
        name_len ++;
        ptr ++;
    }
    return -1;
}

//option check: option_name/0/digital/0
static bool check_option(uint8_t * ptr, uint16_t len )
{
    //option name not too long, like "blksize", "tsize"
    int left = len > 20  ? 20: len;
    uint8_t * ptr_end = ptr + left;
    int opt_len =0 ;
    bool  name_got = false;

    while ( ptr < ptr_end) {
        if (!name_got) {
            if (*ptr == 0 && opt_len >= 4) {
                name_got = true;
                opt_len = 0;
            } else if (!isalpha(*ptr)) {
                return false;
            }
            opt_len ++;
        } else {
            if (*ptr == 0 && opt_len >= 1) {
                return true;
            } else if (!isdigit(*ptr)) {
                return false;
            }
            opt_len ++;
        }
        ptr ++;
    }
    return false;
}

//mode: netascii,octet,mail
static bool check_mode(uint8_t * ptr, uint16_t len )
{
    //all three combine no more than 20 bytes
    int left = len > 20  ? 20: len;
    uint8_t * ptr_end = ptr + left;
    int name_len =0 ;
    uint8_t  name[20];
    bool match = false;

    while ( ptr < ptr_end) {
        if (*ptr == 0 && match) {
            return true;
        } else if (!isalpha(*ptr)) {
                return false ;
        }

        name[name_len++] = toupper(*ptr); 

        if (name_len == 4 && memcmp(name,"MAIL", 4) == 0) {
            name_len = 0;
            match = true;
        } else if(name_len == 5 && memcmp(name,"OCTET", 5) == 0) {
            name_len = 0;
            match = true;
        } else if(name_len == 8 && memcmp(name,"NETASCII", 8) == 0) {
            name_len = 0;
            match = true;
        }
        ptr ++;
    }
    return false;
}

static void tftp_udp_parser(dpi_packet_t *p)
{
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    if (p->sport != 69 && p->dport != 69) {
        dpi_fire_parser(p);
        return;
    }
    len = dpi_pkt_len(p);
    ptr = dpi_pkt_ptr(p);

    if (len < 4 ) {
        return ;
    }
    uint16_t opcode = htons(*(uint16_t *)(ptr));

    if (opcode != TFTP_RRQ && opcode != TFTP_WRQ && opcode != TFTP_DATA && 
            opcode != TFTP_ACK && opcode != TFTP_ERROR && opcode != TFTP_OACK && opcode != TFTP_INFO) {
        dpi_fire_parser(p);
        return ;
    }

    len -= 2;
    ptr += 2;
    //read/write
    if (opcode == TFTP_RRQ || opcode == TFTP_WRQ) {
        int nlen = check_file_name(ptr, len);
        if (nlen == -1) {
            dpi_fire_parser(p);
            return ;
        }
        ptr += nlen;
        len -= nlen;
        if (len < 4) {
            dpi_fire_parser(p);
            return ;
        }
        if (check_mode(ptr, len)) {
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        } else {
            dpi_fire_parser(p);
        }

    } else if (opcode == TFTP_OACK) { 
        if (check_option(ptr, len)) {
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
        } else {
            dpi_fire_parser(p);
        }
    }

}

static void tftp_new_session(dpi_packet_t *p)
{
    if (p->sport != 69 && p->dport != 69) {
        return;
    }
    dpi_hire_parser(p);
}

static dpi_parser_t dpi_parser_tftp_udp = {
    .new_session = tftp_new_session,
    .delete_data = NULL,
    .parser = tftp_udp_parser,
    .name = "tftp",
    .ip_proto = IPPROTO_UDP,
    .type = DPI_PARSER_TFTP,
};

dpi_parser_t *dpi_tftp_udp_parser(void)
{
    return &dpi_parser_tftp_udp;
}
