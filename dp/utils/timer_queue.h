#ifndef __TIMEOUT_QUEUE_H_
#define __TIMEOUT_QUEUE_H_

#include "urcu/list.h"

typedef struct timer_node_ {
    struct cds_list_head link;
    uint32_t last;
} timer_node_t;

typedef void (*timer_queue_remove_fct)(timer_node_t *n);

typedef struct timer_queue_ {
    struct cds_list_head head;
    uint32_t count;
    uint32_t timeout;
} timer_queue_t;

void timer_queue_init(timer_queue_t *q, uint32_t timeout);
void timer_queue_touch(timer_queue_t *q, timer_node_t *n, uint32_t now);
void timer_queue_remove(timer_queue_t *q, timer_node_t *n);
void timer_queue_append(timer_queue_t *q, timer_node_t *n, uint32_t now);
uint32_t timer_queue_trim(timer_queue_t *q, uint32_t now, timer_queue_remove_fct remove);
uint32_t timer_queue_purge(timer_queue_t *q, timer_queue_remove_fct remove);

static inline uint32_t timer_node_last(timer_node_t *n) {
    return n->last;
}

#endif
