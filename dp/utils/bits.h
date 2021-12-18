#ifndef __DP_BITS_H__
#define __DP_BITS_H__

#include <stdlib.h>
#include <string.h>

#define INDEX2MASK(index) (1 << (index))

#define BITMASK_ARRAY_INDEX(x) ((x) >> 3)
#define BITMASK_BIT(x) ((x) & 7)
#define BITMASK_MASK(x) (1 << BITMASK_BIT(x))
#define BITMASK_ARRAY_SIZE(x) BITMASK_ARRAY_INDEX((x) + 7)

#define BITMASK_DEFINE(var, bits) \
    uint8_t var[BITMASK_ARRAY_SIZE(bits)]

#define BITMASK_SET(var, bit) \
    var[BITMASK_ARRAY_INDEX(bit)] |= BITMASK_MASK(bit)

#define BITMASK_UNSET(var, bit) \
    var[BITMASK_ARRAY_INDEX(bit)] &= ~BITMASK_MASK(bit)

#define BITMASK_TEST(var, bit) \
    (var[BITMASK_ARRAY_INDEX(bit)] & BITMASK_MASK(bit))

static inline bool BITMASK_ANY_TEST(uint8_t *v, int size)
{
    int i;
    for (i = 0; (i < BITMASK_ARRAY_SIZE(size)); i ++) {
        if (v[i]) return true;
    }   
    return false;
}

static inline bool BITMASK_RANGE_TEST (uint8_t *a, int min, int max)
{
    int i;
    for (i = min; i < max; i++) {
        if (BITMASK_TEST(a, i)) {
            return true;
        }
    }
    return false;
}

static inline void BITMASK_SET_ALL (uint8_t *a, int numbits)
{
    memset(a, 0xff, BITMASK_ARRAY_SIZE(numbits));
}

static inline void BITMASK_CLEAR_ALL (uint8_t *a, int numbits)
{
    memset(a, 0, BITMASK_ARRAY_SIZE(numbits));
}

#define FLAGS_SET(f, b)   (f |= b)
#define FLAGS_UNSET(f, b) (f &= ~b)
#define FLAGS_TEST(f, b)  (f & b)

/* =========================== BITOP =========================== */

typedef struct BITOP_ {
    uint8_t *buffer;
    int bits;
} BITOP;

#define BITOP_ZERO {0, 0}

static inline void boDestroyBITOP (BITOP *bitop)
{
    if (bitop->buffer != NULL) {
        free(bitop->buffer);
        bitop->buffer = NULL;
    }

    bitop->bits = 0;
}

static inline BITOP *boInitBITOP (BITOP *bitop, int numbits)
{
    if (bitop->buffer != NULL) {
        boDestroyBITOP(bitop);
    }

    bitop->buffer = calloc(1, BITMASK_ARRAY_SIZE(numbits));
    if (bitop->buffer == NULL) {
        return NULL;
    }

    bitop->bits = numbits;

    return bitop;
}

static inline void boSetAllBITOP (BITOP *bitop)
{
    BITMASK_SET_ALL(bitop->buffer, bitop->bits);
}

static inline void boResetBITOP (BITOP *bitop)
{
    BITMASK_CLEAR_ALL(bitop->buffer, bitop->bits);
}

static inline void boSetBit (BITOP *bitop, int pos)
{
    BITMASK_SET(bitop->buffer, pos);
}

static inline bool boIsBitSet (BITOP *bitop, int pos)
{
    return BITMASK_TEST(bitop->buffer, pos);
}

static inline void boClearBit(BITOP *bitop, int pos)
{
    BITMASK_UNSET(bitop->buffer, pos);
}

#endif
