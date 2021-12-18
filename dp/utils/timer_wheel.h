#ifndef __TIMER_WHEEL_H_
#define __TIMER_WHEEL_H_

#include "urcu/list.h"

#define MAX_TIMER_SLOTS 3600

typedef struct timer_wheel_ {
    struct cds_list_head slots[MAX_TIMER_SLOTS];
	uint32_t count;
    uint32_t current;
} timer_wheel_t;

void timer_wheel_init(timer_wheel_t *w);
void timer_wheel_start(timer_wheel_t *w, uint32_t now);
uint32_t timer_wheel_roll(timer_wheel_t *w, uint32_t now);

static inline uint32_t timer_wheel_current(timer_wheel_t *w)
{
    return w->current;
}

static inline uint32_t timer_wheel_count(timer_wheel_t *w)
{
    return w->count;
}

static inline bool timer_wheel_started(timer_wheel_t *w)
{
    return w->current > 0;
}

struct timer_entry_;
typedef void (*timer_wheel_expire_fct)(struct timer_entry_ *n);

#ifdef DEBUG_TIMER_WHEEL
typedef struct debug_entry_ {
    void *caller[4];
    void *callback;
    uint8_t act;
} debug_entry_t;
#endif

typedef struct timer_entry_ {
    struct cds_list_head link;
	timer_wheel_expire_fct callback;
    uint16_t expire_slot;
    uint16_t timeout;
#ifdef DEBUG_TIMER_WHEEL
    debug_entry_t history[16];
    int debugs;
#endif
} timer_entry_t;

void timer_wheel_entry_init(timer_entry_t *n);
void timer_wheel_entry_insert(timer_wheel_t *w, timer_entry_t *n, uint32_t now);
void timer_wheel_entry_refresh(timer_wheel_t *w, timer_entry_t *n, uint32_t now);
void timer_wheel_entry_remove(timer_wheel_t *w, timer_entry_t *n);
void timer_wheel_entry_start(timer_wheel_t *w, timer_entry_t *n,
                             timer_wheel_expire_fct cb, uint16_t timeout, uint32_t now);

static inline void timer_wheel_entry_set_callback(timer_entry_t *n, timer_wheel_expire_fct cb)
{
    n->callback = cb;
}

static inline uint16_t timer_wheel_entry_get_timeout(timer_entry_t *n)
{
	return n->timeout;
}

static inline void timer_wheel_entry_set_timeout(timer_entry_t *n, uint16_t timeout)
{
    if (unlikely(timeout >= MAX_TIMER_SLOTS)) {
        return;
    }

    n->timeout = timeout;
}

uint16_t timer_wheel_entry_get_idle(const timer_entry_t *n, uint32_t now);
uint16_t timer_wheel_entry_get_life(const timer_entry_t *n, uint32_t now);

static inline bool timer_wheel_entry_is_active(const timer_entry_t *n)
{
    //return (n->expire_slot == (uint16_t)(-1)) ? false : true;
    return n->callback ? true : false;
}

#endif
