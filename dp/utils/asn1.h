#ifndef __ASN1_H__
#define __ASN1_H__

#include "helper.h"

enum {
    ASN1_ERR_NONE = 0,
    ASN1_ERR_LONG,
    ASN1_ERR_FORMAT,
};

typedef enum {
    ASN1_CLASS_UNIVERSAL   = 0,
    ASN1_CLASS_APPLICATION = 1,
    ASN1_CLASS_CONTEXT     = 2,
    ASN1_CLASS_PRIVATE     = 3,
} ans1_class_t;

// https://www.obj-sys.com/asn1tutorial/node124.html
typedef enum {
    ASN1_TAG_RESERVED   = 0,     // Reserved for BER
    ASN1_TAG_BOOLEAN    = 1,     // BOOLEAN                  
    ASN1_TAG_INTEGER    = 2,     // INTEGER                  
    ASN1_TAG_BITSTR     = 3,     // BIT STRING               
    ASN1_TAG_OCTSTR     = 4,     // OCTET STRING             
    ASN1_TAG_NULL       = 5,     // NULL
    ASN1_TAG_OBJID      = 6,     // OBJECT IDENTIFIER
    ASN1_TAG_OBJDESC    = 7,     // Object Descriptor
    ASN1_TAG_INSTANCE   = 8,     // INSTANCE OF, EXTERNAL
    ASN1_TAG_REAL       = 9,     // REAL                    
    ASN1_TAG_ENUMERATED = 10,    // ENUMERATED               
    ASN1_TAG_EMBPDV     = 11,    // EMBEDDED PDV
    ASN1_TAG_UTF8STR    = 12,    // UTF8 STRING
    ASN1_TAG_RELOID     = 13,    // RELATIVE-OID             
    ASN1_TAG_SEQUENCE   = 16,    // SEQUENCE, SEQUENCE of     
    ASN1_TAG_SET        = 17,    // SET, SET OF
    ASN1_TAG_NUMSTR     = 18,    // NumericString            
    ASN1_TAG_PRINTSTR   = 19,    // PrintableString         
    ASN1_TAG_TELESTR    = 20,    // TeletexString, T61String 
    ASN1_TAG_VIDEOSTR   = 21,    // VideotexString
    ASN1_TAG_IA5STR     = 22,    // IA5String                
    ASN1_TAG_UTCTIME    = 23,    // UTCTime           
    ASN1_TAG_GENTIME    = 24,    // GeneralizedTime
    ASN1_TAG_GRASTR     = 25,    // GraphicString
    ASN1_TAG_VISSTR     = 26,    // VisibleString, ISO646String
    ASN1_TAG_GENSTR     = 27,    // GeneralString           
    ASN1_TAG_UNIVSTR    = 28,    // UniversalString
    ASN1_TAG_CHARSTR    = 29,    // CHARACTER STRING
    ASN1_TAG_BMPSTR     = 30,    // BMPString
    ASN1_TAG_VARYSIZE   = 31,
} asn1_tag_t;

typedef struct asn1_ {
    int length;
    uint8_t class;
    uint8_t tag;
    bool constructed;
} asn1_t;

typedef struct asn_oid_ {
    uint32_t len;
#define ASN1_MAX_OID_LEN  128 
    uint32_t oid[ASN1_MAX_OID_LEN];
} asn1_oid_t;

int asn1_parse_bool(asn1_t *asn1, buf_t *buf);
int asn1_parse_integer(asn1_t *asn1, buf_t *buf, int *value);
int asn1_parse_octstr(asn1_t *asn1, buf_t *buf);
int asn1_parse_bitstr(asn1_t *asn1, buf_t *buf);
int asn1_parse_ia5str(asn1_t *asn1, buf_t *buf);
int asn1_parse_charstr(asn1_t *asn1, buf_t *buf);
int asn1_parse_printstr(asn1_t *asn1, buf_t *buf);
int asn1_parse_sequence(asn1_t *asn1, buf_t *buf);
int asn1_parse_setseq(asn1_t *asn1, buf_t *buf);
int asn1_parse_oid(asn1_t *asn1, buf_t *buf, asn1_oid_t *oid);
int asn1_parse_enum(asn1_t *asn1, buf_t *buf, int *value);
int asn1_parse_object(asn1_t *asn1, buf_t *buf);

int asn1_read_header(asn1_t *asn1, buf_t *buf);
int asn1_read_integer(asn1_t *asn1, buf_t *buf, int *value);
int asn1_read_string(asn1_t *asn1, buf_t *buf);
int asn1_read_oid(asn1_t *asn1, buf_t *buf, asn1_oid_t *oid);

#endif
