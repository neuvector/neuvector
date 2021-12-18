#ifndef __ASM_H__
#define __ASM_H__

#include <stdint.h>

#include "tree.h"

typedef struct clip_ {
    tree_node_t node;

    uint8_t *ptr;
    uint32_t seq;
    uint32_t len : 24,
             action:3;
    uint16_t skip;
} clip_t;

typedef void (*asm_remove_func_t)(clip_t *clip);
typedef void (*asm_foreach_func_t)(clip_t *clip, void *args);

typedef struct asm_ {
    tree_t tree;

    uint32_t gross;
} asm_t;


typedef enum asm_result_ {
    ASM_OK = 0,
    ASM_FAILURE,
    ASM_NOP,
    ASM_MORE,
} asm_result_t;


void asm_init(asm_t *a);
asm_result_t asm_insert(asm_t *a, clip_t *clip);
clip_t *asm_lookup(asm_t *a, uint32_t seq);
void asm_remove(asm_t *a, clip_t *clip, asm_remove_func_t remove);
void asm_destroy(asm_t *a, asm_remove_func_t remove);
void asm_flush(asm_t *a, uint32_t seq, asm_remove_func_t remove);
void asm_foreach(asm_t *a, asm_foreach_func_t foreach, void *args);
asm_result_t asm_construct(asm_t *a, clip_t *target, uint32_t must_have);

static inline uint32_t asm_count(asm_t *a)
{
    return tree_count_node(&a->tree);
}


static inline uint32_t asm_gross(asm_t *a)
{
    return a->gross;
}

#endif
