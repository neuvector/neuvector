#include <stdio.h>
#include "asn1.h"

#define ASN1_GET_CLASS(c)      ((c & 0xc0) >> 6)
#define ASN1_GET_TAG(c)        (c & 0x1f)
#define ASN1_IS_CONSTRUCTED(c) ((c & 0X20) != 0)

int asn1_read_integer(asn1_t *asn1, buf_t *buf, int *value)
{
    int count, v = 0;

    if (asn1->length > 4) {
        buf->seq += asn1->length;
        return ASN1_ERR_LONG;
    }

    count = asn1->length;
    while (count > 0) {
        v = (v << 8) | buf->ptr[buf->seq];
        buf->seq ++;
        count --;
    }

    *value = v;
    return ASN1_ERR_NONE;
}

int asn1_read_string(asn1_t *asn1, buf_t *buf)
{
    buf->seq += asn1->length;
    return ASN1_ERR_NONE;
}


#define ASN1_MAX_NODE_ID 0xffffffff
int asn1_read_oid(asn1_t *asn1, buf_t *buf, asn1_oid_t *oid)
{
    uint8_t ch;
    uint32_t node, oid_end = buf->seq + asn1->length;

    oid->len = 0;
    if (asn1->length == 0) return ASN1_ERR_FORMAT;

    while (buf->seq < oid_end) {
        if (oid->len >= ASN1_MAX_OID_LEN) {
            return ASN1_ERR_FORMAT;
        }

        node = 0;
        do {
            if (buf->seq >= buf->len) return ASN1_ERR_FORMAT;
            if (node > (ASN1_MAX_NODE_ID >> 7)) return ASN1_ERR_FORMAT;
            ch = *(buf->ptr + buf->seq);
            node = (node << 7) | (ch & 0x7f);
            buf->seq ++;
        } while (ch >= 0x80);

        if (oid->len == 0) {
            if (node < 80) {
                oid->oid[oid->len++] = node / 40;
                oid->oid[oid->len++] = node % 40;
            } else {
                oid->oid[oid->len++] = 2;
                oid->oid[oid->len++] = node - 80;
            }
        } else {
            oid->oid[oid->len++] = node;
        }
    }

    return ASN1_ERR_NONE;
}


static int asn1_read_tag(asn1_t *asn1, buf_t *buf)
{
    uint8_t ch;
    int tag = 0;

    do {
        if (buf->seq >= buf->len) return ASN1_ERR_FORMAT;

        ch = *(buf->ptr + buf->seq);
        tag = (tag << 7) | (ch & 0x7f);
        buf->seq ++;
    } while (ch >= 0x80);

    if (tag < 0) return ASN1_ERR_FORMAT;

    asn1->tag = tag;

    return ASN1_ERR_NONE; 
}


static int asn1_read_length(asn1_t *asn1, buf_t *buf)
{
    int length = 0, count;

    if (buf->seq >= buf->len) return ASN1_ERR_FORMAT;

    uint8_t ch = buf->ptr[buf->seq];
    if (ch == 0x80) return ASN1_ERR_FORMAT;
    if (ch == 0xff) return ASN1_ERR_FORMAT;
    if (ch < 0x80) {
        asn1->length = ch;
        buf->seq ++;
        return ASN1_ERR_NONE;
    }

    buf->seq ++;

    count = ch & 0x7f;
    if (buf->seq + count >= buf->len) return ASN1_ERR_FORMAT;
    if (count > 4) return ASN1_ERR_FORMAT;

    while (count > 0) {
        ch = buf->ptr[buf->seq];
        length = (length << 8) | ch;
        count --;
        buf->seq ++;
    }

    if (length < 0) return ASN1_ERR_FORMAT;

    asn1->length = length;

    return ASN1_ERR_NONE;
}

int asn1_read_header(asn1_t *asn1, buf_t *buf)
{
    if (buf->len < 2 || buf->seq >= buf->len) return ASN1_ERR_FORMAT;

    uint8_t ch = buf->ptr[buf->seq];
    asn1->class = ASN1_GET_CLASS(ch);
    asn1->constructed = ASN1_IS_CONSTRUCTED(ch);
    asn1->tag = ASN1_GET_TAG(ch);

    buf->seq ++;
    
    if (asn1->tag == ASN1_TAG_VARYSIZE) {
        int ret = asn1_read_tag(asn1, buf);
        if (ret != ASN1_ERR_NONE) return ret;
    }
    
    int ret = asn1_read_length(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (buf->seq + asn1->length > buf->len) return ASN1_ERR_FORMAT;

    return ASN1_ERR_NONE;
}

int asn1_parse_bool(asn1_t *asn1, buf_t *buf)
{
    uint8_t id, len, v;

    if (buf->seq + 3 >= buf->len) return ASN1_ERR_FORMAT;
    id = buf->ptr[buf->seq];
    len = buf->ptr[buf->seq + 1];
    v = buf->ptr[buf->seq + 2];

    // must be 0101ff or 010100
    if (id == 1 && len == 1 && (v == 0 || v == 0xff)) {
        buf->seq += 3;
        return ASN1_ERR_NONE;
    }

    return ASN1_ERR_FORMAT;
}

int asn1_parse_integer(asn1_t *asn1, buf_t *buf, int *value)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (asn1->constructed || asn1->tag != ASN1_TAG_INTEGER) return ASN1_ERR_FORMAT;

    return asn1_read_integer(asn1, buf, value);
}

int asn1_parse_enum(asn1_t *asn1, buf_t *buf, int *value)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (asn1->constructed || asn1->tag != ASN1_TAG_ENUMERATED) return ASN1_ERR_FORMAT;

    return asn1_read_integer(asn1, buf, value);
}


static int asn1_parse_string(asn1_t *asn1, buf_t *buf, int tag)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (asn1->constructed || (asn1->tag != tag && asn1->tag != ASN1_TAG_NULL)) return ASN1_ERR_FORMAT;

    return asn1_read_string(asn1, buf);
}

int asn1_parse_octstr(asn1_t *asn1, buf_t *buf)
{
    return asn1_parse_string(asn1, buf, ASN1_TAG_OCTSTR);
}

int asn1_parse_bitstr(asn1_t *asn1, buf_t *buf)
{
    return asn1_parse_string(asn1, buf, ASN1_TAG_BITSTR);
}

int asn1_parse_charstr(asn1_t *asn1, buf_t *buf)
{
    return asn1_parse_string(asn1, buf, ASN1_TAG_CHARSTR);
}

int asn1_parse_printstr(asn1_t *asn1, buf_t *buf)
{
    return asn1_parse_string(asn1, buf, ASN1_TAG_PRINTSTR);
}

int asn1_parse_ia5str(asn1_t *asn1, buf_t *buf)
{
    return asn1_parse_string(asn1, buf, ASN1_TAG_IA5STR);
}

int asn1_parse_sequence(asn1_t *asn1, buf_t *buf)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (!asn1->constructed || asn1->tag != ASN1_TAG_SEQUENCE) return ASN1_ERR_FORMAT;

    return ASN1_ERR_NONE;
}

int asn1_parse_setseq(asn1_t *asn1, buf_t *buf)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (!asn1->constructed || asn1->tag != ASN1_TAG_SET) return ASN1_ERR_FORMAT;

    return ASN1_ERR_NONE;
}


int asn1_parse_oid(asn1_t *asn1, buf_t *buf, asn1_oid_t *oid)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;
    if (asn1->constructed || asn1->tag != ASN1_TAG_OBJID) return ASN1_ERR_FORMAT;

    return asn1_read_oid(asn1, buf, oid);
}


int asn1_parse_object(asn1_t *asn1, buf_t *buf)
{
    int ret = asn1_read_header(asn1, buf);
    if (ret != ASN1_ERR_NONE) return ret;

    buf->seq += asn1->length;
    return ASN1_ERR_NONE;
}
