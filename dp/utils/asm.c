#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils/helper.h"
#include "utils/asm.h"

static int asm_compare(void *node, tree_node_t *key)
{
    clip_t *n = (clip_t *)node;
    clip_t *k = (clip_t *)key;

    if (u32_gt(n->seq, k->seq)) {
        return 1;
    } else if (u32_lt(n->seq, k->seq)) {
        return -1;
    } else {
        return 0;
    }
}

void asm_init(asm_t *a)
{
    tree_init(&a->tree, asm_compare);
    a->gross = 0;
}

clip_t *asm_lookup(asm_t *a, uint32_t seq)
{
    clip_t clip;

    clip.seq = seq;
    return (clip_t *)tree_find_node(&a->tree, &clip.node);
}


asm_result_t asm_insert(asm_t *a, clip_t *clip)
{
    tree_init_node(&clip->node);

    if (tree_insert_node(&a->tree, &clip->node) == NULL) {
        return ASM_FAILURE;
    } else {
        a->gross += clip->len;
        return ASM_OK;
    }
}

void asm_remove(asm_t *a, clip_t *clip, asm_remove_func_t remove)
{
    if (tree_remove_node(&a->tree, &clip->node) != NULL) {
        a->gross -= clip->len;
    }
    remove(clip);
}


void asm_destroy(asm_t *a, asm_remove_func_t remove)
{
    tree_destroy(&a->tree, (tree_remove_func_t)remove);
    a->gross = 0;
}


void asm_flush(asm_t *a, uint32_t seq, asm_remove_func_t remove)
{
    clip_t *clip, *next;

    if (asm_count(a) == 0) return;

    clip = (clip_t *)tree_first_node((tree_node_t *)(&a->tree));
    while (clip != NULL) {
        next = (clip_t *)tree_next_node(&clip->node);

        if (u32_lte(clip->seq + clip->len, seq)) {
            asm_remove(a, clip, remove);
        } else {
            break;
        }

        clip = next;
    }
}


void asm_foreach(asm_t *a, asm_foreach_func_t foreach, void *args)
{
    tree_traverse(&a->tree, (tree_each_func_t)foreach, args);
}


asm_result_t asm_construct(asm_t *a, clip_t *target, uint32_t must_have)
{
    clip_t *itr, *next, *first, *last;
    uint32_t end, total = 0;

    if (asm_count(a) <= 1) {
        return ASM_NOP;
    }

    first = (clip_t *)tree_first_node((tree_node_t *)(&a->tree));

    // Traverse the tree to find the assembly range
    itr = last = first;
    while (itr != NULL) {
        last = itr;
        next = (clip_t *)tree_next_node(&itr->node);

        end = itr->seq + itr->len;
        total = max(total, end - first->seq);
        if (u32_lte(end, target->seq)) {
            // Move forward as the current clip is too early
            first = last = next;
        } else if (next != NULL && u32_lt(end, next->seq)) {
            // Gap! 
            if (u32_lt(end, must_have)) {
                return ASM_NOP;
            } else {
                break;
            }
        }

        itr = next;
    }

    if (first == last || u32_lt(target->seq, first->seq)) {
        return ASM_NOP;
    }

    if (total > target->len) {
        target->seq = first->seq;
        target->len = total;
        return ASM_MORE;
    }

    target->len = 0;
    itr = first;
    while (itr) {
        next = (itr == last) ? NULL : (clip_t *)tree_next_node(&itr->node);

        end = itr->seq + itr->len;
        memcpy(target->ptr + (itr->seq - first->seq), itr->ptr + itr->skip, itr->len);
        target->len = max(end - first->seq, target->len);

        itr = next;
    }

    target->seq = first->seq;

    return ASM_OK;
}

