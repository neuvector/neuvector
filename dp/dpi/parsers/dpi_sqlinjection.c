#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

typedef bool (*sql_injection_callback_t)(dpi_packet_t *p, pcre2_code *recompiled, char *signature,
       int  substr_values, uint8_t *query, int len);

typedef struct sql_injection_ {
    sql_injection_callback_t cb;
    pcre2_code *recompiled;
    int  substr_values;
    char * signature; 
} sql_injection_t;

static bool injection_0 (dpi_packet_t *p, pcre2_code *recompiled, char *signature,
                                int substr_value, uint8_t *query, int len) {
    bool match = false;
    pcre2_match_data * match_data;
    PCRE2_SIZE *ovector;

    if(recompiled  == NULL) {
        DEBUG_LOG(DBG_PARSER, p, "ERROR: PCRE2 signature is not compiled '%s'\n", signature);
        return match;
    } 
    match_data = pcre2_match_data_create_from_pattern(recompiled, NULL);

    if (match_data == NULL) {
        DEBUG_LOG(DBG_PARSER, p, "ERROR: PCRE2 match data block cannot be allocated\n");
        return match;
    }

    int rc = pcre2_match(recompiled, (PCRE2_SPTR)query, len, 0, 0, match_data, NULL);

    /* Matching failed: handle error cases */
    if (rc < 0) { 
        switch(rc){
            case PCRE2_ERROR_NOMATCH: 
                DEBUG_LOG(DBG_PARSER, p, "PCRE2 Pattern does not match\n");
                break;
            default: 
                DEBUG_LOG(DBG_PARSER, p, "PCRE2 Matching error %d\n", rc);
                break;
        }
    } else {
        /* Match succeded. Get a pointer to the output vector, where string offsets are
        stored. */
        ovector = pcre2_get_ovector_pointer(match_data);
        DEBUG_LOG(DBG_PARSER, NULL, "Match succeeded between offset0 %d and offset1 %d\n", (int)ovector[0],(int)ovector[1]);
        match = true;

        /*if (rc == substr_value) {
            char *x0,*x1;
            pcre2_substring_get_bynumber(match_data, 2, (PCRE2_UCHAR **)(&x0), ovector);
            pcre2_substring_get_bynumber(match_data, 3, (PCRE2_UCHAR **)(&x1), ovector);
            if (x0 != NULL && x1 != NULL && strcmp(x0, x1) == 0) {
                match = true;
            }
            pcre2_substring_free((PCRE2_UCHAR *)x0);
            pcre2_substring_free((PCRE2_UCHAR *)x1);
        }*/
    }
    pcre2_match_data_free(match_data);
    return match;
}

static sql_injection_t sql_injections[] ={   
//SELECT * FROM users WHERE name='adam' or 'x' = 'x'
{injection_0, NULL, 0, "(?i)^SELECT.*\'\\s+(?:or|OR)\\s+((?:\'|\")?[0-9a-zA-Z_]+(?:\'|\")?)\\s*=\\s*\\1"},
};

void sql_injection_init()
{
    int pcre_errno;
    PCRE2_SIZE pcre_erroroffset;

    int i;
    for (i=0; i<sizeof(sql_injections)/sizeof(sql_injections[0]); i++) {
        pcre2_code * recompiled = pcre2_compile((PCRE2_SPTR)sql_injections[i].signature,
                                                PCRE2_ZERO_TERMINATED,
                                                0,
                                                &pcre_errno,
                                                &pcre_erroroffset,
                                                NULL);
        if(recompiled == NULL) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(pcre_errno, buffer, sizeof(buffer));
            DEBUG_LOG(DBG_CTRL, NULL, "ERROR: PCRE2 compilation for (%s) failed at offset %d: %s\n", 
                        sql_injections[i].signature, pcre_errno, buffer);
        } 
        sql_injections[i].recompiled = recompiled;
    }
}

//Embedded sql-injection threat detection based on PCRE pattern matching
void check_sql_query(dpi_packet_t *p, uint8_t *query, int len, int app)
{
    int i;
    for (i=0; i<sizeof(sql_injections)/sizeof(sql_injections[0]); i++) {
        if (sql_injections[i].cb(p, sql_injections[i].recompiled, 
                                 sql_injections[i].signature, 
                                 sql_injections[i].substr_values,
                                 query, len)) {
            dpi_threat_trigger(DPI_THRT_SQL_INJECTION, p, 
                    "SQL Injection, application=%d", app);
        }
    }
}
