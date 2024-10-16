#include <string.h>

#include "utils/asn1.h"
#include "dpi/dpi_module.h"

#define FORMAT_MATCH  0
#define FORMAT_WRONG  1
#define FORMAT_IGNORE 2
#define FORMAT_DEFER  3

#define SSL_NONE       0x0000
#define SSL_2_2BYTE    0x0002
#define SSL_2_3BYTE    0x0003
#define SSL_2_PCT      0x0200
#define SSL_3_0        0x0300
#define TLS_1_0        0x0301
#define TLS_1_1        0x0302
#define TLS_1_2        0x0303

#define PCT_CLIENT_HELLO           1
#define PCT_SERVER_HELLO           2
#define PCT_CLIENT_MASTER_KEY      3
#define PCT_SERVER_VERYFY          4
#define PCT_ERROR                  5

#define SSL3_HS_HELLO_REQUEST           0
#define SSL3_HS_CLIENT_HELLO            1
#define SSL3_HS_SERVER_HELLO            2
#define SSL3_HS_CERTIFICATE             11
#define SSL3_HS_SERVER_KEY_EXC          12
#define SSL3_HS_CERTIF_REQUEST          13
#define SSL3_HS_SERVER_HELLO_DONE       14
#define SSL3_HS_CERTIF_VERIFY           15
#define SSL3_HS_CLIENT_KEY_EXC          16
#define SSL3_HS_FINISHED                20

#define SSL2_MSG_ERROR               0
#define SSL2_MSG_CLIENT_HELLO        1
#define SSL2_MSG_CLIENT_MASTER_KEY   2
#define SSL2_MSG_CLIENT_FINISHED     3
#define SSL2_MSG_SERVER_HELLO        4
#define SSL2_MSG_SERVER_VERIFY       5
#define SSL2_MSG_SERVER_FINISHED     6
#define SSL2_MSG_REQUEST_CERTIFICATE 7
#define SSL2_MSG_CLIENT_CERTIFICATE  8

#define SSL3_RT_CHANGE_CIPHER_SPEC 20
#define SSL3_RT_ALERT              21
#define SSL3_RT_HANDSHAKE          22
#define SSL3_RT_APPLICATION_DATA   23
#define SSL3_RT_HEARTBEAT          24

#define SSL3_HBT_REQUEST  1
#define SSL3_HBT_RESPONSE 2

static asn1_oid_t X520_OID_COMMON_NAME = {4, {2, 5, 4, 3}};

typedef struct ssl_record_ {
    uint16_t ver;
    uint16_t len;
    uint8_t  type;
} ssl_record_t;

typedef struct ssl_wing_ {
    u_int32_t seq;
    uint8_t match     :1,
            encrypted :1;
} ssl_wing_t;

typedef struct ssl_data_ {
    ssl_wing_t client, server;
    uint16_t version;
} ssl_data_t;

/* https://tools.ietf.org/html/rfc5280

   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
*/

static int ssl_parse_x509(dpi_packet_t *p, uint8_t *ptr, int len)
{
    asn1_t asn1;
    asn1_oid_t oid;
    buf_t buf;
    int ret = ASN1_ERR_NONE;
    int ver, dummy;

    oid.len = 0;

    buf.ptr = ptr;
    buf.len = len;
    buf.seq = 0;

    ret = asn1_parse_sequence(&asn1, &buf);
    if (ret != ASN1_ERR_NONE) return ret;

    // TBSCertificate 
    ret = asn1_parse_sequence(&asn1, &buf);
    if (ret != ASN1_ERR_NONE) return ret;

    // version, Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    ret = asn1_read_header(&asn1, &buf);
    if (asn1.class != ASN1_CLASS_CONTEXT) {
        // serialNumber, CertificateSerialNumber  ::=  INTEGER
        ret = asn1_read_integer(&asn1, &buf, &dummy);
        if (ret != ASN1_ERR_NONE && ret != ASN1_ERR_LONG) return ret;
    } else {
        ret = asn1_read_header(&asn1, &buf);
        ret = asn1_read_integer(&asn1, &buf, &ver);
        if (ret != ASN1_ERR_NONE) return ret;
        if (ver > 2) {
            return ASN1_ERR_FORMAT;
        }
        // serialNumber, CertificateSerialNumber  ::=  INTEGER
        ret = asn1_read_header(&asn1, &buf);
        ret = asn1_read_integer(&asn1, &buf, &dummy);
        if (ret != ASN1_ERR_NONE && ret != ASN1_ERR_LONG) return ret;
    }

    // signature, AlgorithmIdentifier  ::=  SEQUENCE  {
    //    algorithm               OBJECT IDENTIFIER,
    //    parameters              ANY DEFINED BY algorithm OPTIONAL  }
    ret = asn1_parse_sequence(&asn1, &buf);
    if (ret != ASN1_ERR_NONE) return ret;
    buf.seq += asn1.length;

    // issuer, Name ::== SEQUENCE(obj)
    ret = asn1_parse_sequence(&asn1, &buf);
    if (ret != ASN1_ERR_NONE) return ret;
    buf.seq += asn1.length;

    // validity, Validity ::== SEQUENCE(obj)
    ret = asn1_parse_sequence(&asn1, &buf);
    if (ret != ASN1_ERR_NONE) return ret;
    buf.seq += asn1.length;

    // subject, Name ::== SEQUENCE(obj)
    while (buf.seq < buf.len) {
        ret = asn1_read_header(&asn1, &buf);
        if (ret != ASN1_ERR_NONE) return ret;

        switch (asn1.tag) {
        case ASN1_TAG_BOOLEAN:
        case ASN1_TAG_INTEGER:
            ret = asn1_read_integer(&asn1, &buf, &ver);
            if (ret != ASN1_ERR_NONE && ret != ASN1_ERR_LONG) return ret;
            break;
        case ASN1_TAG_OBJID:
            ret = asn1_read_oid(&asn1, &buf, &oid);
            if (ret != ASN1_ERR_NONE && ret != ASN1_ERR_LONG) return ret;
            break;
        case ASN1_TAG_UTCTIME:
        case ASN1_TAG_GENTIME:
            buf.seq += asn1.length;
            break;
        case ASN1_TAG_NUMSTR:
        case ASN1_TAG_TELESTR:
        case ASN1_TAG_VIDEOSTR:
        case ASN1_TAG_GRASTR:
        case ASN1_TAG_VISSTR:
        case ASN1_TAG_GENSTR:
        case ASN1_TAG_UNIVSTR:
        case ASN1_TAG_CHARSTR:
        case ASN1_TAG_BMPSTR:
        case ASN1_TAG_BITSTR:
        case ASN1_TAG_UTF8STR:
        case ASN1_TAG_IA5STR:
        case ASN1_TAG_OCTSTR:
        case ASN1_TAG_PRINTSTR:
            ret = asn1_read_string(&asn1, &buf);
            if (ret != ASN1_ERR_NONE && ret != ASN1_ERR_LONG) return ret;

            if (oid.len >= 4 && memcmp(X520_OID_COMMON_NAME.oid, oid.oid, 16) == 0) {
                DEBUG_LOG(DBG_PARSER, p, "SSL common name: %.*s\n",
                          asn1.length, buf.ptr + buf.seq - asn1.length);
            }
            break;
        default:
            break;
        }
    }

    return ret;
}

/* RFC 6347
 * struct {
 *     ProtocolVersion client_version;
 *     Random random;
 *     SessionID session_id;
 *     opaque cookie<0..2^8-1>;
 *     CipherSuite cipher_suites<2..2^16-1>;
 *     CompressionMethod compression_methods<1..2^8-1>;
 * } ClientHello;
 */
int ssl_parse_handshake_v3(dpi_packet_t *p, ssl_wing_t *w, uint8_t *ptr, ssl_record_t *rec)
{
    uint8_t *end = ptr + rec->len;

    while (ptr < end) {
        uint8_t type = *ptr;
        uint32_t len = GET_BIG_INT24(ptr + 1);
        ptr += 4;

        if (len > rec->len - 4) {
            DEBUG_LOG(DBG_PARSER, p, "\tnot SSL-cmd longer than record\n");
            return FORMAT_WRONG;
        }

        if (type == SSL3_HS_CERTIFICATE) {
            int cert_len = GET_BIG_INT24(ptr + 3);
            int ret = ssl_parse_x509(p, ptr + 6, cert_len);
            if (ret != ASN1_ERR_NONE) {
                DEBUG_LOG(DBG_PARSER, p, "Invalid certificate\n");
            }
        }

        ptr += len;
    }

    return FORMAT_MATCH;
}

void ssl_get_sni_v3(dpi_packet_t *p, uint8_t *ptr, ssl_record_t *rec)
{
    uint8_t *tptr = ptr;
    uint8_t *end = tptr + rec->len;
    dpi_session_t *s = p->session;

    uint16_t len = 0;
    tptr += 6;//handshake type(1) + length(3) + version(2)
    tptr += 32;//random(32)
    len = (uint16_t)(*(uint8_t *)(tptr));//session id
    //DEBUG_LOG(DBG_PARSER, p, "session id length %hu\n", len);
    tptr += 1;
    tptr += len;
    len = GET_BIG_INT16(tptr);//cipher suite
    //DEBUG_LOG(DBG_PARSER, p, "cipher suite length %hu\n", len);
    tptr += 2;
    tptr += len;
    len = (uint16_t)(*(uint8_t *)(tptr));//compression method
    //DEBUG_LOG(DBG_PARSER, p, "compression method length %hu\n", len);
    tptr += 1;
    tptr += len;
    len = GET_BIG_INT16(tptr);//extension length
    //DEBUG_LOG(DBG_PARSER, p, "extension length %hu\n", len);
    tptr += 2;
    if ((tptr + len) != end) {
        DEBUG_LOG(DBG_PARSER, p, "Mismatch length!\n");
        return;
    }
    uint16_t ext_type = 1;
    uint16_t ext_len;
    while (tptr < end) {
        ext_type = GET_BIG_INT16(tptr);
        tptr += 2;
        ext_len = GET_BIG_INT16(tptr);
        tptr += 2;
        if(ext_type == 0)
        {
            tptr += 3;
            uint16_t namelen = GET_BIG_INT16(tptr);
            tptr += 2;
            //DEBUG_LOG(DBG_PARSER, p, "ssl: snilen(%hu), sniname(%s)\n", namelen,(char *)tptr);
            int size = min(namelen+1, sizeof(s->vhost));
            strlcpy((char *)s->vhost, (char *)tptr, size);
            s->vhlen = size-1;
            tptr += namelen;
            break;
        } else {
            tptr += ext_len;
        }
    }
    DEBUG_LOG(DBG_PARSER, p, "sniname(%s) vhlen(%hu)\n", (char *)s->vhost, s->vhlen);
}

int ssl_parse_v3(dpi_packet_t *p, ssl_wing_t *w, uint8_t *ptr, ssl_record_t *rec)
{
    int ret = FORMAT_MATCH;

    switch (rec->type) {
    case SSL3_RT_CHANGE_CIPHER_SPEC:
        DEBUG_LOG(DBG_PARSER, p, "SSLv3: change cipher spec\n");
        w->encrypted = true;
        break;
    case SSL3_RT_ALERT:
        DEBUG_LOG(DBG_PARSER, p, "SSLv3: alert\n");
        break;
    case SSL3_RT_HANDSHAKE:
        DEBUG_LOG(DBG_PARSER, p, "SSLv3: Handshake\n");

        uint8_t handshake_type = ptr[0];
        if (handshake_type == SSL3_HS_CLIENT_HELLO) {
            if (!dpi_is_client_pkt(p)) {
                return FORMAT_WRONG;
            }
            rec->ver = GET_BIG_INT16(ptr + 4);
            ssl_get_sni_v3(p, ptr, rec);
        } else if (handshake_type == SSL3_HS_SERVER_HELLO) {
            if (dpi_is_client_pkt(p)) {
                return FORMAT_WRONG;
            }
            rec->ver = GET_BIG_INT16(ptr + 4);
        }

        if (!w->encrypted) {
            ret = ssl_parse_handshake_v3(p, w, ptr, rec);
        }
        break;
    case SSL3_RT_APPLICATION_DATA:
        DEBUG_LOG(DBG_PARSER, p, "SSLv3: data\n");
        break;
    case SSL3_RT_HEARTBEAT:
        DEBUG_LOG(DBG_PARSER, p, "SSLv3: heartbeat\n");

        if (ptr[0] == SSL3_HBT_REQUEST) {
            uint16_t hbt_len = GET_BIG_INT16(ptr + 1);
            // 1024 is a min size to reduce false positive.
            if (hbt_len - (rec->len - 3) > 1024) {
                DEBUG_ERROR(DBG_PARSER, "SSLv3: heartbleed, heartbeat=%u record=%u\n", hbt_len, rec->len);
                dpi_threat_trigger(DPI_THRT_SSL_HEARTBLEED, p, "heartbeat=%u, record=%u", hbt_len, rec->len);
            }
        }
        break;
    }

    return ret;
}

int ssl_parse_v2(dpi_packet_t *p, ssl_wing_t *w, uint8_t *ptr, int len, ssl_record_t *rec)
{
    rec->type = ptr[0];

    switch (rec->type) {
    case SSL2_MSG_ERROR:
        DEBUG_LOG(DBG_PARSER, p, "SSLv2: error message\n");
        break;
    case SSL2_MSG_CLIENT_HELLO:
        DEBUG_LOG(DBG_PARSER, p, "SSLv2: client hello message\n");

        rec->ver = GET_BIG_INT16(ptr + 1);

        if (rec->len >= 9) {
            if (len < 9) return FORMAT_DEFER;

            uint16_t cipher_len = GET_BIG_INT16(ptr + 3);
            uint16_t session_id_len = GET_BIG_INT16(ptr + 5);
            uint16_t challenge_len = GET_BIG_INT16(ptr + 7);
            uint16_t expect;

            expect = rec->len - 9 - session_id_len - challenge_len;
            if (cipher_len == expect) {
                return FORMAT_MATCH;
            } else if (cipher_len > expect) {
                // sslv2 cipher length overflow
                DEBUG_ERROR(DBG_PARSER, "SSLv2: cipher length overflow\n");
                dpi_threat_trigger(DPI_THRT_SSL_CIPHER_OVF, p, "SSL version: SSLv2");
                return FORMAT_IGNORE;
            } else {
                return FORMAT_IGNORE;
            }
        } else {
            DEBUG_LOG(DBG_PARSER, p, "no SSL-v2: header too short\n");
            return FORMAT_WRONG;
        }
        break;
    case SSL2_MSG_CLIENT_MASTER_KEY:
        DEBUG_LOG(DBG_PARSER, p, "SSLv2: client master key message\n");
        w->encrypted = true;
        break;
    case SSL2_MSG_SERVER_HELLO:
        DEBUG_LOG(DBG_PARSER, p, "SSLv2: server hello message\n");

        rec->ver = GET_BIG_INT16(ptr + 3);

        if (rec->len >= 11) {
            if (len < 11) return FORMAT_DEFER;

            uint16_t cert_len = GET_BIG_INT16(ptr + 5);
            uint16_t cipher_len = GET_BIG_INT16(ptr + 7);
            uint16_t connection_id_len = GET_BIG_INT16(ptr + 9);
            uint16_t expect;

            expect = rec->len - 11 - connection_id_len - cert_len;
            if (cipher_len == expect) {
                return FORMAT_MATCH;
            } else {
                return FORMAT_IGNORE;
            }
        } else {
            DEBUG_LOG(DBG_PARSER, p, "not SSL-v2: header too short\n");
            return FORMAT_WRONG;
        }
        break;
    default:
        DEBUG_LOG(DBG_PARSER, p, "not SSLv2: unknown message=%d\n", rec->type);
        return FORMAT_WRONG;
    }

    return FORMAT_MATCH;
}

// Only check first client and server packet.
static int get_ssl_ver(dpi_packet_t *p, uint8_t *ptr, uint16_t len)
{
    u_int16_t rlen, ver;
    u_int8_t type;

    // Check if the record is SSLv3
    type = ptr[0];
    ver = GET_BIG_INT16(ptr + 1);
    rlen = GET_BIG_INT16(ptr + 3);
    DEBUG_LOG(DBG_PARSER, p, "SSLv3? record ver=0x%x type=%d len=%d\n", ver, type, rlen);

    // Check the record types valid in the first packet of SSLv3
    if ((type == SSL3_RT_CHANGE_CIPHER_SPEC || type == SSL3_RT_ALERT ||
         type == SSL3_RT_HANDSHAKE) &&
        (ver == SSL_3_0 || ver == TLS_1_0 || ver == TLS_1_1 || ver == TLS_1_2)) {
        return ver;
    }

    // Check if the record is SSLv2
    if (ptr[0] >= 0x80) {
        // Check if record len in 2-byte
        rlen = ((ptr[0] & 0x7f) << 8) + ptr[1];
        type = ptr[2];
        if (type == SSL2_MSG_SERVER_HELLO) {
            ver = GET_BIG_INT16(ptr + 5);
        } else {
            ver = GET_BIG_INT16(ptr + 3);
        }

        DEBUG_LOG(DBG_PARSER, p, "SSLv2? record ver=0x%x type=%d len=%d\n", ver, type, rlen);

        if (ver == SSL_2_2BYTE || ver == SSL_3_0 || ver == TLS_1_0 ||
            ver == TLS_1_1 || ver == TLS_1_2) {
            if ((type == SSL2_MSG_ERROR && rlen == len - 2) ||
                type == SSL2_MSG_CLIENT_HELLO || type == SSL2_MSG_SERVER_HELLO) {
                return SSL_2_2BYTE;
            }
        } else if (ver >= 0x0100 && ver < 0x0300 && type == PCT_CLIENT_HELLO) {
            if (rlen <= len - 2 && len > 11 &&
                GET_BIG_INT16(ptr + 5) == 1 && GET_BIG_INT16(ptr + 7) == 1 &&
                GET_BIG_INT16(ptr + 9) >= 16 && GET_BIG_INT16(ptr + 9) <= 32) {
                return SSL_2_PCT;
            }
        }
    } else {
        rlen = ((ptr[0] & 0x3f) << 8) + ptr[1];

        if (!dpi_is_client_pkt(p) || rlen == len - 3) {
            return SSL_2_3BYTE;
        }
    }

    return SSL_NONE;
}

static void ssl_parser(dpi_packet_t *p)
{
    ssl_data_t *data;
    ssl_wing_t *w;
    uint8_t *ptr;
    uint32_t len;

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not SSL: First packet from server\n");
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

#define SSL_MIN_RECORD_LEN 7 // minimum length to determine ssl version
#define SSL_MAX_RECORD_LEN 8192
    ssl_record_t rec;
    while (len > SSL_MIN_RECORD_LEN) {
        if (!dpi_is_parser_final(p)) {
            int ver = get_ssl_ver(p, ptr, len);
            int ignore = false;

            switch (ver) {
            case SSL_3_0:
            case TLS_1_0:
            case TLS_1_1:
            case TLS_1_2:
                data->version = ver;

                rec.type = ptr[0];
                rec.ver = GET_BIG_INT16(ptr + 1);
                rec.len = GET_BIG_INT16(ptr + 3);
                ptr += 5;
                len -= 5;

                if (rec.len > SSL_MAX_RECORD_LEN) {
                    DEBUG_LOG(DBG_PARSER, p, "SSLv3: long record\n");
                    dpi_ignore_parser(p);
                    return;
                }

                if (len < rec.len) return;

                switch (ssl_parse_v3(p, w, ptr, &rec)) {
                case FORMAT_MATCH:
                    w->match = true;
                    break;
                case FORMAT_WRONG:
                    DEBUG_LOG(DBG_PARSER, p, "not SSLv3: wrong format\n");
                    dpi_fire_parser(p);
                    return;
                case FORMAT_IGNORE:
                    DEBUG_LOG(DBG_PARSER, p, "ignore SSLv3:\n");
                    w->match = true;
                    ignore = true;
                    break;
                }

                if (rec.ver == SSL_3_0) {
                    dpi_threat_trigger(DPI_THRT_SSL_VER_2OR3, p, "SSL version: SSLv3");
                } else if (rec.ver == TLS_1_0) {
                    dpi_threat_trigger(DPI_THRT_SSL_TLS_1DOT0, p, "TLS version: TLS1.0");
                } else if (rec.ver == TLS_1_1) {
                    dpi_threat_trigger(DPI_THRT_SSL_TLS_1DOT1, p, "TLS version: TLS1.1");
                }
                break;
            case SSL_2_2BYTE:
                data->version = ver;

                rec.len = GET_BIG_INT16(ptr) - 0x8000;
                ptr += 2;
                len -= 2;

                switch (ssl_parse_v2(p, w, ptr, len, &rec)) {
                case FORMAT_DEFER:
                    return;
                case FORMAT_MATCH:
                    w->match = true;
                    break;
                case FORMAT_WRONG:
                    DEBUG_LOG(DBG_PARSER, p, "not SSL: wrong sslv2 format\n");
                    dpi_fire_parser(p);
                    return;
                case FORMAT_IGNORE:
                    DEBUG_LOG(DBG_PARSER, p, "ignore SSLv2:\n");
                    w->match = true;
                    ignore = true;
                    break;
                }

                dpi_threat_trigger(DPI_THRT_SSL_VER_2OR3, p, NULL);
                break;
            case SSL_2_3BYTE:
                // Sometimes similar to email protocols, ignore it.
                DEBUG_LOG(DBG_PARSER, p, "SSLv2 encrypt: ignore\n");
                dpi_fire_parser(p);
                return;
            case SSL_2_PCT:
                DEBUG_LOG(DBG_PARSER, p, "SSL PCT: skip\n");
                dpi_fire_parser(p);
                return;
            default:
                DEBUG_LOG(DBG_PARSER, p, "not SSL\n");
                dpi_fire_parser(p);
                return;
            }

            if (data->client.match && data->server.match) {
                DEBUG_LOG(DBG_PARSER, p, "SSL final: ver=0x%x\n", data->version);
                dpi_finalize_parser(p);

                if (ignore) {
                    dpi_ignore_parser(p);
                }
            }
        } else {
            if (data->version == SSL_2_2BYTE) {
                DEBUG_LOG(DBG_PARSER, p, "SSLv2: ignore\n");
                dpi_ignore_parser(p);
                return;
            } else if (data->version == SSL_3_0 || data->version == TLS_1_0 ||
                       data->version == TLS_1_1 || data->version == TLS_1_2 ) {
                rec.type = ptr[0];
                rec.ver = GET_BIG_INT16(ptr + 1);
                rec.len = GET_BIG_INT16(ptr + 3);
                ptr += 5;
                len -= 5;

                if (rec.type == SSL3_RT_APPLICATION_DATA) {
                    DEBUG_LOG(DBG_PARSER, p, "SSLv3: data portion, ignore\n");
                    dpi_ignore_parser(p);
                    return;
                }

                if (rec.len > SSL_MAX_RECORD_LEN) {
                    DEBUG_LOG(DBG_PARSER, p, "SSLv3: long record\n");
                    dpi_ignore_parser(p);
                    return;
                }

                if (len < rec.len) return;

                switch (ssl_parse_v3(p, w, ptr, &rec)) {
                case FORMAT_WRONG:
                case FORMAT_IGNORE:
                    DEBUG_LOG(DBG_PARSER, p, "SSLv3: wrong format, ignore\n");
                    dpi_ignore_parser(p);
                    break;
                }
            }
        }

        if (len >= rec.len) {
            ptr += rec.len;
            len -= rec.len;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);
        } else {
            return;
        }
    }
}


static void ssl_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);
}

static void ssl_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_ssl = {
    new_session: ssl_new_session,
    delete_data: ssl_delete_data,
    parser:      ssl_parser,
    name:        "ssl",
    ip_proto:    IPPROTO_TCP,
    type:        DPI_PARSER_SSL,
};

dpi_parser_t *dpi_ssl_parser(void)
{
    return &dpi_parser_ssl;
}
