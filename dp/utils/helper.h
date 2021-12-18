#ifndef __DP_UTILS_H__
#define __DP_UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct buf_ {
	uint8_t *ptr;
	uint32_t len;
	uint32_t seq;
} buf_t;

#define ALIGN_UP(value, poweroftwo) (((value) + ((poweroftwo) - 1)) & ~((poweroftwo) - 1))
#define STRUCT_OF(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define ARRAY_ENTRIES(array) sizeof(array) / sizeof(array[0])
#define DPI_MAX_PORTS  65536
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);
char *strip_str(char *s);
char *strip_str_quote(char *s);
char **str_split(const char *s, const char *delim, int *count);
void free_split(char **tokens, int count);
bool parse_int_range(uint32_t *low, uint32_t *high, const char *range, int max);


static inline uint64_t htonll(uint64_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t high_part = htonl((uint32_t)(value >> 32));
    uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
    return ((uint64_t)(low_part) << 32) | high_part;
#else
    return value;
#endif
}

static inline bool mac_zero(uint8_t *m)
{
    return *(uint32_t *)m == 0 && *(uint16_t *)(m + 4) == 0;
}

static inline bool mac_cmp(uint8_t *m1, uint8_t *m2)
{
    return *(uint32_t *)m1 == *(uint32_t *)m2 &&
           *(uint16_t *)(m1 + 4) == *(uint16_t *)(m2 + 4);
}

static inline void mac_cpy(uint8_t *m1, uint8_t *m2)
{
    *(uint32_t *)m1 = *(uint32_t *)m2;
    *(uint16_t *)(m1 + 4) = *(uint16_t *)(m2 + 4);
}

static inline void ip4_cpy(uint8_t *ip1, uint8_t *ip2)
{
    *(uint32_t *)ip1 = *(uint32_t *)ip2;
}

static inline uint32_t ip4_get(uint8_t *ip)
{
    return *(uint32_t *)ip;
}

static inline uint32_t sdbm_hash(register const uint8_t *a, register int len)
{
    register uint32_t hash = 0;

    while (len > 0) {
        hash = *a + (hash << 6) + (hash << 16) - hash;
        a ++; len --;
    }

    return hash;
}

#define CONSUME_TOKEN_SKIP_LINE 1
typedef int (*token_func_t) (void *param, uint8_t *ptr, int len, int token_idx);

uint8_t *consume_string(uint8_t *ptr, int len);
uint8_t *consume_line(uint8_t *ptr, int len, int *eol_chars);
void consume_tokens(uint8_t *ptr, int len, token_func_t func, void *param);
void lower_string(char* s);

int count_cpu(void);

static inline uint32_t u32_distance(uint32_t u1, uint32_t u2)
{
    return u2 - u1;
}

static inline bool u32_lt(uint32_t u1, uint32_t u2)
{
    return (signed)(u1 - u2) < 0;
}

static inline bool u32_lte(uint32_t u1, uint32_t u2)
{
    return (signed)(u1 - u2) <= 0;
}

static inline bool u32_gt(uint32_t u1, uint32_t u2)
{
    return (signed)(u1 - u2) > 0;
}

static inline bool u32_gte(uint32_t u1, uint32_t u2)
{
    return (signed)(u1 - u2) >= 0;
}

// u1 <= u < u2
static inline bool u32_between(uint32_t u, uint32_t u1, uint32_t u2)
{
    return (u2 - u1 > u - u1);
}

// [u1, u2) overlap [u3, u4)
static inline bool u32_overlap(uint32_t u1, uint32_t u2, uint32_t u3, uint32_t u4)
{
	return u1 < u4 && u2 > u3;
}

static inline bool is_mac_bcast(uint8_t* mac) 
{
    uint16_t *a = (uint16_t *)mac;
    return ( (a[0] ^ 0xffff) | (a[1] ^ 0xffff) | (a[2] ^ 0xffff)) == 0;
}

static inline bool is_mac_m_b_cast(uint8_t* mac) 
{
    uint16_t a = *(uint16_t *)mac;
	return 0x01 & a;
}



#define GET_BIG_INT16(v) \
    ((*(uint8_t *)(v) << 8) | (*((uint8_t *)(v) + 1)))
#define GET_BIG_INT24(v) \
    ((*(uint8_t *)(v) << 16) | (*((uint8_t *)(v) + 1) << 8) | (*((uint8_t *)(v) + 2)))
#define GET_BIG_INT32(v) \
    ((*(uint8_t *)(v) << 24) | (*((uint8_t *)(v) + 1) << 16) | \
	 (*((uint8_t *)(v) + 2) << 8) | (*((uint8_t *)(v) + 3)))
#define GET_LITTLE_INT16(v) \
    ((*(uint8_t *)(v)) | (*((uint8_t *)(v) + 1) << 8))
#define GET_LITTLE_INT24(v) \
    ((* (uint8_t *)(v)) | (*((uint8_t *)(v) + 1) << 8) | (*((uint8_t *)(v) + 2) << 16))

#define ctoi(c) ((c) - '0')
int8_t c2hex(uint8_t c);

#define IS_IN_LOOPBACK(i)		(((u_int32_t)(i) & 0xff000000) == 0x7f000000)

#endif

