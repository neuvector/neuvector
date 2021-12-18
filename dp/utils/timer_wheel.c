#include <sys/types.h>
#include <string.h>
#include <stdint.h>

#include "utils/timer_wheel.h"
#include "utils/helper.h"


void timer_wheel_init(timer_wheel_t *w)
{
    int i;

    for (i = 0; i < MAX_TIMER_SLOTS; i ++) {
        CDS_INIT_LIST_HEAD(&w->slots[i]);
    }
    w->current = w->count = 0;
}

void timer_wheel_start(timer_wheel_t *w, uint32_t now)
{
    w->current = now;
}

uint32_t timer_wheel_roll(timer_wheel_t *w, uint32_t now)
{
    if (now < w->current) {
        return 0;
    }

    uint32_t cnt = 0;
    uint32_t s, m = min(now, w->current + MAX_TIMER_SLOTS);
    for (s = w->current; s < m; s ++) {
        struct cds_list_head *head = &w->slots[s % MAX_TIMER_SLOTS];

        // Because link entries can be modified in callback, so we cannot use
        // cds_list_for_each_entry_safe() to walk through the list; instead, we remove
        // the head every time and start over again until the link is empty.
        while (!cds_list_empty(head)) {
            timer_entry_t *itr = cds_list_first_entry(head, timer_entry_t, link);
            timer_wheel_expire_fct fn = itr->callback;
            timer_wheel_entry_remove(w, itr);
            fn(itr);
            cnt ++;
        }
    }

    w->current = now;

    return cnt;
}

void timer_wheel_entry_init(timer_entry_t *n)
{
    CDS_INIT_LIST_HEAD(&n->link);
    n->expire_slot = (uint16_t)(-1);
    n->callback = NULL;
}

#ifdef DEBUG_TIMER_WHEEL
#include <assert.h>
#define INSERT 0
#define REMOVE 1
#endif

void timer_wheel_entry_insert(timer_wheel_t *w, timer_entry_t *n, uint32_t now)
{
#ifdef DEBUG_TIMER_WHEEL
    void *c1 = __builtin_return_address(0);
//    void *c2 = __builtin_return_address(1);
//    void *c3 = __builtin_return_address(2);
//    void *c4 = __builtin_return_address(3);
    if (n->debugs < 16) {
        n->history[n->debugs].caller[0] = c1;
//        n->history[n->debugs].caller2 = c2;
//        n->history[n->debugs].caller3 = c3;
//        n->history[n->debugs].caller4 = c4;
//        backtrace(n->history[n->debugs].caller, 4);
        n->history[n->debugs].callback = n->callback;
        n->history[n->debugs].act = INSERT;
        n->debugs ++;
        if (n->debugs >= 2 && n->history[n->debugs - 2].act == INSERT) {
            assert(0);
        }
    }
#endif

    uint32_t expire_at = now + n->timeout;
    n->expire_slot = expire_at % MAX_TIMER_SLOTS;
    cds_list_add_tail(&n->link, &w->slots[n->expire_slot]);
    w->count ++;
}

void timer_wheel_entry_refresh(timer_wheel_t *w, timer_entry_t *n, uint32_t now)
{
    timer_wheel_expire_fct fn = n->callback;
    timer_wheel_entry_remove(w, n);
    n->callback = fn;
    timer_wheel_entry_insert(w, n, now);
}

void timer_wheel_entry_remove(timer_wheel_t *w, timer_entry_t *n)
{
#ifdef DEBUG_TIMER_WHEEL
    void *c1 = __builtin_return_address(0);
//    void *c2 = __builtin_return_address(1);
//    void *c3 = __builtin_return_address(2);
//    void *c4 = __builtin_return_address(3);
    if (n->debugs < 16) {
        n->history[n->debugs].caller[0] = c1;
//        n->history[n->debugs].caller2 = c2;
//        n->history[n->debugs].caller3 = c3;
//        n->history[n->debugs].caller4 = c4;
//        backtrace(n->history[n->debugs].caller, 4);
        n->history[n->debugs].callback = n->callback;
        n->history[n->debugs].act = REMOVE;
        n->debugs ++;
        if (n->debugs < 2) {
            assert(0);
        }
        if (n->history[n->debugs - 2].act == REMOVE) {
            assert(0);
        }
        if (n->history[n->debugs - 2].act == INSERT) {
            n->debugs -= 2;
        }
    }
#endif

    cds_list_del(&n->link);
    w->count --;
    //n->expire_slot = (uint16_t)(-1);
    n->callback = NULL;
}

void timer_wheel_entry_start(timer_wheel_t *w, timer_entry_t *n,
                             timer_wheel_expire_fct cb, uint16_t timeout, uint32_t now)
{
    if (unlikely(timeout >= MAX_TIMER_SLOTS)) {
        timeout = 0;
    }

    n->callback = cb;
    n->timeout = timeout;

    timer_wheel_entry_insert(w, n, now);
}

static uint32_t get_expire_at(const timer_entry_t *n, uint32_t now)
{
    uint16_t slot = now % MAX_TIMER_SLOTS;
    if (n->callback == NULL || n->expire_slot >= slot) {
        return now + n->expire_slot - slot;
    } else {
        return now + n->expire_slot + MAX_TIMER_SLOTS - slot;
    }
}

uint16_t timer_wheel_entry_get_idle(const timer_entry_t *n, uint32_t now)
{
    return (uint16_t)(now - (get_expire_at(n, now) - n->timeout));
}

uint16_t timer_wheel_entry_get_life(const timer_entry_t *n, uint32_t now)
{
    return (uint16_t)(get_expire_at(n, now) - now);
}

