#ifndef _URCU_DEFER_IMPL_H
#define _URCU_DEFER_IMPL_H

/*
 * urcu-defer-impl.h
 *
 * Userspace RCU header - memory reclamation.
 *
 * TO BE INCLUDED ONLY FROM URCU LIBRARY CODE. See urcu-defer.h for linking
 * dynamically with the userspace rcu reclamation library.
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * IBM's contributions to this file may be relicensed under LGPLv2 or later.
 */

#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>

#include "urcu/futex.h"

#include <urcu/compiler.h>
#include <urcu/arch.h>
#include <urcu/uatomic.h>
#include <urcu/list.h>
#include <urcu/system.h>
#include <urcu/tls-compat.h>
#include "urcu-die.h"

/*
 * Number of entries in the per-thread defer queue. Must be power of 2.
 */
#define DEFER_QUEUE_SIZE	(1 << 12)
#define DEFER_QUEUE_MASK	(DEFER_QUEUE_SIZE - 1)

/*
 * Typically, data is aligned at least on the architecture size.
 * Use lowest bit to indicate that the current callback is changing.
 * Assumes that (void *)-2L is not used often. Used to encode non-aligned
 * functions and non-aligned data using extra space.
 * We encode the (void *)-2L fct as: -2L, fct, data.
 * We encode the (void *)-2L data as either:
 *   fct | DQ_FCT_BIT, data (if fct is aligned), or
 *   -2L, fct, data (if fct is not aligned).
 * Here, DQ_FCT_MARK == ~DQ_FCT_BIT. Required for the test order.
 */
#define DQ_FCT_BIT		(1 << 0)
#define DQ_IS_FCT_BIT(x)	((unsigned long)(x) & DQ_FCT_BIT)
#define DQ_SET_FCT_BIT(x)	\
	(x = (void *)((unsigned long)(x) | DQ_FCT_BIT))
#define DQ_CLEAR_FCT_BIT(x)	\
	(x = (void *)((unsigned long)(x) & ~DQ_FCT_BIT))
#define DQ_FCT_MARK		((void *)(~DQ_FCT_BIT))

/*
 * This code section can only be included in LGPL 2.1 compatible source code.
 * See below for the function call wrappers which can be used in code meant to
 * be only linked with the Userspace RCU library. This comes with a small
 * performance degradation on the read-side due to the added function calls.
 * This is required to permit relinking with newer versions of the library.
 */

#ifdef DEBUG_RCU
#define rcu_assert(args...)	assert(args)
#else
#define rcu_assert(args...)
#endif

/*
 * defer queue.
 * Contains pointers. Encoded to save space when same callback is often used.
 * When looking up the next item:
 * - if DQ_FCT_BIT is set, set the current callback to DQ_CLEAR_FCT_BIT(ptr)
 *   - next element contains pointer to data.
 * - else if item == DQ_FCT_MARK
 *   - set the current callback to next element ptr
 *   - following next element contains pointer to data.
 * - else current element contains data
 */
struct defer_queue {
	unsigned long head;	/* add element at head */
	void *last_fct_in;	/* last fct pointer encoded */
	unsigned long tail;	/* next element to remove at tail */
	void *last_fct_out;	/* last fct pointer encoded */
	void **q;
	/* registry information */
	unsigned long last_head;
	struct cds_list_head list;	/* list of thread queues */
};

/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#include "urcu-defer.h"

void __attribute__((destructor)) rcu_defer_exit(void);

extern void synchronize_rcu(void);

/*
 * rcu_defer_mutex nests inside defer_thread_mutex.
 */
static pthread_mutex_t rcu_defer_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t defer_thread_mutex = PTHREAD_MUTEX_INITIALIZER;

static int32_t defer_thread_futex;
static int32_t defer_thread_stop;

/*
 * Written to only by each individual deferer. Read by both the deferer and
 * the reclamation tread.
 */
static DEFINE_URCU_TLS(struct defer_queue, defer_queue);
static CDS_LIST_HEAD(registry_defer);
static pthread_t tid_defer;

static void mutex_lock_defer(pthread_mutex_t *mutex)
{
	int ret;

#ifndef DISTRUST_SIGNALS_EXTREME
	ret = pthread_mutex_lock(mutex);
	if (ret)
		urcu_die(ret);
#else /* #ifndef DISTRUST_SIGNALS_EXTREME */
	while ((ret = pthread_mutex_trylock(mutex)) != 0) {
		if (ret != EBUSY && ret != EINTR)
			urcu_die(ret);
		poll(NULL,0,10);
	}
#endif /* #else #ifndef DISTRUST_SIGNALS_EXTREME */
}

/*
 * Wake-up any waiting defer thread. Called from many concurrent threads.
 */
static void wake_up_defer(void)
{
	if (caa_unlikely(uatomic_read(&defer_thread_futex) == -1)) {
		uatomic_set(&defer_thread_futex, 0);
		if (futex_noasync(&defer_thread_futex, FUTEX_WAKE, 1,
				NULL, NULL, 0) < 0)
			urcu_die(errno);
	}
}

static unsigned long rcu_defer_num_callbacks(void)
{
	unsigned long num_items = 0, head;
	struct defer_queue *index;

	mutex_lock_defer(&rcu_defer_mutex);
	cds_list_for_each_entry(index, &registry_defer, list) {
		head = CMM_LOAD_SHARED(index->head);
		num_items += head - index->tail;
	}
	mutex_unlock(&rcu_defer_mutex);
	return num_items;
}

/*
 * Defer thread waiting. Single thread.
 */
static void wait_defer(void)
{
	uatomic_dec(&defer_thread_futex);
	/* Write futex before read queue */
	/* Write futex before read defer_thread_stop */
	cmm_smp_mb();
	if (_CMM_LOAD_SHARED(defer_thread_stop)) {
		uatomic_set(&defer_thread_futex, 0);
		pthread_exit(0);
	}
	if (rcu_defer_num_callbacks()) {
		cmm_smp_mb();	/* Read queue before write futex */
		/* Callbacks are queued, don't wait. */
		uatomic_set(&defer_thread_futex, 0);
	} else {
		cmm_smp_rmb();	/* Read queue before read futex */
		if (uatomic_read(&defer_thread_futex) != -1)
			return;
		while (futex_noasync(&defer_thread_futex, FUTEX_WAIT, -1,
				NULL, NULL, 0)) {
			switch (errno) {
			case EWOULDBLOCK:
				/* Value already changed. */
				return;
			case EINTR:
				/* Retry if interrupted by signal. */
				break;	/* Get out of switch. */
			default:
				/* Unexpected error. */
				urcu_die(errno);
			}
		}
	}
}

/*
 * Must be called after Q.S. is reached.
 */
static void rcu_defer_barrier_queue(struct defer_queue *queue,
				    unsigned long head)
{
	unsigned long i;
	void (*fct)(void *p);
	void *p;

	/*
	 * Tail is only modified when lock is held.
	 * Head is only modified by owner thread.
	 */

	for (i = queue->tail; i != head;) {
		cmm_smp_rmb();       /* read head before q[]. */
		p = CMM_LOAD_SHARED(queue->q[i++ & DEFER_QUEUE_MASK]);
		if (caa_unlikely(DQ_IS_FCT_BIT(p))) {
			DQ_CLEAR_FCT_BIT(p);
			queue->last_fct_out = p;
			p = CMM_LOAD_SHARED(queue->q[i++ & DEFER_QUEUE_MASK]);
		} else if (caa_unlikely(p == DQ_FCT_MARK)) {
			p = CMM_LOAD_SHARED(queue->q[i++ & DEFER_QUEUE_MASK]);
			queue->last_fct_out = p;
			p = CMM_LOAD_SHARED(queue->q[i++ & DEFER_QUEUE_MASK]);
		}
		fct = queue->last_fct_out;
		fct(p);
	}
	cmm_smp_mb();	/* push tail after having used q[] */
	CMM_STORE_SHARED(queue->tail, i);
}

static void _rcu_defer_barrier_thread(void)
{
	unsigned long head, num_items;

	head = URCU_TLS(defer_queue).head;
	num_items = head - URCU_TLS(defer_queue).tail;
	if (caa_unlikely(!num_items))
		return;
	synchronize_rcu();
	rcu_defer_barrier_queue(&URCU_TLS(defer_queue), head);
}

void rcu_defer_barrier_thread(void)
{
	mutex_lock_defer(&rcu_defer_mutex);
	_rcu_defer_barrier_thread();
	mutex_unlock(&rcu_defer_mutex);
}

/*
 * rcu_defer_barrier - Execute all queued rcu callbacks.
 *
 * Execute all RCU callbacks queued before rcu_defer_barrier() execution.
 * All callbacks queued on the local thread prior to a rcu_defer_barrier() call
 * are guaranteed to be executed.
 * Callbacks queued by other threads concurrently with rcu_defer_barrier()
 * execution are not guaranteed to be executed in the current batch (could
 * be left for the next batch). These callbacks queued by other threads are only
 * guaranteed to be executed if there is explicit synchronization between
 * the thread adding to the queue and the thread issuing the defer_barrier call.
 */

void rcu_defer_barrier(void)
{
	struct defer_queue *index;
	unsigned long num_items = 0;

	if (cds_list_empty(&registry_defer))
		return;

	mutex_lock_defer(&rcu_defer_mutex);
	cds_list_for_each_entry(index, &registry_defer, list) {
		index->last_head = CMM_LOAD_SHARED(index->head);
		num_items += index->last_head - index->tail;
	}
	if (caa_likely(!num_items)) {
		/*
		 * We skip the grace period because there are no queued
		 * callbacks to execute.
		 */
		goto end;
	}
	synchronize_rcu();
	cds_list_for_each_entry(index, &registry_defer, list)
		rcu_defer_barrier_queue(index, index->last_head);
end:
	mutex_unlock(&rcu_defer_mutex);
}

/*
 * _defer_rcu - Queue a RCU callback.
 */
static void _defer_rcu(void (*fct)(void *p), void *p)
{
	unsigned long head, tail;

	/*
	 * Head is only modified by ourself. Tail can be modified by reclamation
	 * thread.
	 */
	head = URCU_TLS(defer_queue).head;
	tail = CMM_LOAD_SHARED(URCU_TLS(defer_queue).tail);

	/*
	 * If queue is full, or reached threshold. Empty queue ourself.
	 * Worse-case: must allow 2 supplementary entries for fct pointer.
	 */
	if (caa_unlikely(head - tail >= DEFER_QUEUE_SIZE - 2)) {
		assert(head - tail <= DEFER_QUEUE_SIZE);
		rcu_defer_barrier_thread();
		assert(head - CMM_LOAD_SHARED(URCU_TLS(defer_queue).tail) == 0);
	}

	/*
	 * Encode:
	 * if the function is not changed and the data is aligned and it is
	 * not the marker:
	 *	store the data
	 * otherwise if the function is aligned and its not the marker:
	 *	store the function with DQ_FCT_BIT
	 *	store the data
	 * otherwise:
	 *	store the marker (DQ_FCT_MARK)
	 *	store the function
	 *	store the data
	 *
	 * Decode: see the comments before 'struct defer_queue'
	 *         or the code in rcu_defer_barrier_queue().
	 */
	if (caa_unlikely(URCU_TLS(defer_queue).last_fct_in != fct
			|| DQ_IS_FCT_BIT(p)
			|| p == DQ_FCT_MARK)) {
		URCU_TLS(defer_queue).last_fct_in = fct;
		if (caa_unlikely(DQ_IS_FCT_BIT(fct) || fct == DQ_FCT_MARK)) {
			_CMM_STORE_SHARED(URCU_TLS(defer_queue).q[head++ & DEFER_QUEUE_MASK],
				      DQ_FCT_MARK);
			_CMM_STORE_SHARED(URCU_TLS(defer_queue).q[head++ & DEFER_QUEUE_MASK],
				      fct);
		} else {
			DQ_SET_FCT_BIT(fct);
			_CMM_STORE_SHARED(URCU_TLS(defer_queue).q[head++ & DEFER_QUEUE_MASK],
				      fct);
		}
	}
	_CMM_STORE_SHARED(URCU_TLS(defer_queue).q[head++ & DEFER_QUEUE_MASK], p);
	cmm_smp_wmb();	/* Publish new pointer before head */
			/* Write q[] before head. */
	CMM_STORE_SHARED(URCU_TLS(defer_queue).head, head);
	cmm_smp_mb();	/* Write queue head before read futex */
	/*
	 * Wake-up any waiting defer thread.
	 */
	wake_up_defer();
}

static void *thr_defer(void *args)
{
	for (;;) {
		/*
		 * "Be green". Don't wake up the CPU if there is no RCU work
		 * to perform whatsoever. Aims at saving laptop battery life by
		 * leaving the processor in sleep state when idle.
		 */
		wait_defer();
		/* Sleeping after wait_defer to let many callbacks enqueue */
		poll(NULL,0,100);	/* wait for 100ms */
		rcu_defer_barrier();
	}

	return NULL;
}

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void defer_rcu(void (*fct)(void *p), void *p)
{
	_defer_rcu(fct, p);
}

static void start_defer_thread(void)
{
	int ret;

	ret = pthread_create(&tid_defer, NULL, thr_defer, NULL);
	assert(!ret);
}

static void stop_defer_thread(void)
{
	int ret;
	void *tret;

	_CMM_STORE_SHARED(defer_thread_stop, 1);
	/* Store defer_thread_stop before testing futex */
	cmm_smp_mb();
	wake_up_defer();

	ret = pthread_join(tid_defer, &tret);
	assert(!ret);

	CMM_STORE_SHARED(defer_thread_stop, 0);
	/* defer thread should always exit when futex value is 0 */
	assert(uatomic_read(&defer_thread_futex) == 0);
}

int rcu_defer_register_thread(void)
{
	int was_empty;

	assert(URCU_TLS(defer_queue).last_head == 0);
	assert(URCU_TLS(defer_queue).q == NULL);
	URCU_TLS(defer_queue).q = malloc(sizeof(void *) * DEFER_QUEUE_SIZE);
	if (!URCU_TLS(defer_queue).q)
		return -ENOMEM;

	mutex_lock_defer(&defer_thread_mutex);
	mutex_lock_defer(&rcu_defer_mutex);
	was_empty = cds_list_empty(&registry_defer);
	cds_list_add(&URCU_TLS(defer_queue).list, &registry_defer);
	mutex_unlock(&rcu_defer_mutex);

	if (was_empty)
		start_defer_thread();
	mutex_unlock(&defer_thread_mutex);
	return 0;
}

void rcu_defer_unregister_thread(void)
{
	int is_empty;

	mutex_lock_defer(&defer_thread_mutex);
	mutex_lock_defer(&rcu_defer_mutex);
	cds_list_del(&URCU_TLS(defer_queue).list);
	_rcu_defer_barrier_thread();
	free(URCU_TLS(defer_queue).q);
	URCU_TLS(defer_queue).q = NULL;
	is_empty = cds_list_empty(&registry_defer);
	mutex_unlock(&rcu_defer_mutex);

	if (is_empty)
		stop_defer_thread();
	mutex_unlock(&defer_thread_mutex);
}

void rcu_defer_exit(void)
{
	assert(cds_list_empty(&registry_defer));
}

#endif /* _URCU_DEFER_IMPL_H */
