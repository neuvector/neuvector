#include <sys/types.h>
#include <string.h>
#include <stdint.h>

#include "utils/timer_queue.h"

void timer_queue_init(timer_queue_t *q, uint32_t timeout)
{
    CDS_INIT_LIST_HEAD(&q->head);
    q->timeout = timeout;
    q->count = 0;
}

void timer_queue_touch(timer_queue_t *q, timer_node_t *n, uint32_t now)
{
    n->last = now;
    cds_list_del(&n->link);
    cds_list_add_tail(&n->link, &q->head);
}

void timer_queue_remove(timer_queue_t *q, timer_node_t *n)
{
    cds_list_del(&n->link);
    q->count --;
}

void timer_queue_append(timer_queue_t *q, timer_node_t *n, uint32_t now)
{
    n->last = now;
    cds_list_add_tail(&n->link, &q->head);
    q->count ++;
}

uint32_t timer_queue_trim(timer_queue_t *q, uint32_t now, timer_queue_remove_fct remove)
{
    uint32_t cnt = 0;
    timer_node_t *itr, *next;

    cds_list_for_each_entry_safe(itr, next, &q->head, link) {
        if (now < itr->last) {
            timer_queue_touch(q, itr, now);
        } else if (now < itr->last + q->timeout) {
            return cnt;
        } else {
            timer_queue_remove(q, itr);
            remove(itr);
            cnt ++;
        }
    }

    return cnt;
}

uint32_t timer_queue_purge(timer_queue_t *q, timer_queue_remove_fct remove)
{
    uint32_t cnt = 0;
    timer_node_t *itr, *next;

    cds_list_for_each_entry_safe(itr, next, &q->head, link) {
        timer_queue_remove(q, itr);
        remove(itr);
        cnt ++;
    }

    return cnt;
}

