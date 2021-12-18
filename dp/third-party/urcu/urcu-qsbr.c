/*
 * urcu-qsbr.c
 *
 * Userspace RCU QSBR library
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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "urcu/wfcqueue.h"
#include "urcu/map/urcu-qsbr.h"
#define BUILD_QSBR_LIB
#include "urcu/static/urcu-qsbr.h"
#include "urcu-pointer.h"
#include "urcu/tls-compat.h"

#include "urcu-die.h"
#include "urcu-wait.h"

/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#undef _LGPL_SOURCE
#include "urcu-qsbr.h"
#define _LGPL_SOURCE

void __attribute__((destructor)) rcu_exit(void);

/*
 * rcu_gp_lock ensures mutual exclusion between threads calling
 * synchronize_rcu().
 */
static pthread_mutex_t rcu_gp_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * rcu_registry_lock ensures mutual exclusion between threads
 * registering and unregistering themselves to/from the registry, and
 * with threads reading that registry from synchronize_rcu(). However,
 * this lock is not held all the way through the completion of awaiting
 * for the grace period. It is sporadically released between iterations
 * on the registry.
 * rcu_registry_lock may nest inside rcu_gp_lock.
 */
static pthread_mutex_t rcu_registry_lock = PTHREAD_MUTEX_INITIALIZER;
struct rcu_gp rcu_gp = { .ctr = RCU_GP_ONLINE };

/*
 * Active attempts to check for reader Q.S. before calling futex().
 */
#define RCU_QS_ACTIVE_ATTEMPTS 100

/*
 * Written to only by each individual reader. Read by both the reader and the
 * writers.
 */
__DEFINE_URCU_TLS_GLOBAL(struct rcu_reader, rcu_reader);

#ifdef DEBUG_YIELD
unsigned int rcu_yield_active;
__DEFINE_URCU_TLS_GLOBAL(unsigned int, rcu_rand_yield);
#endif

static CDS_LIST_HEAD(registry);

/*
 * Queue keeping threads awaiting to wait for a grace period. Contains
 * struct gp_waiters_thread objects.
 */
static DEFINE_URCU_WAIT_QUEUE(gp_waiters);

static void mutex_lock(pthread_mutex_t *mutex)
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

static void mutex_unlock(pthread_mutex_t *mutex)
{
	int ret;

	ret = pthread_mutex_unlock(mutex);
	if (ret)
		urcu_die(ret);
}

/*
 * synchronize_rcu() waiting. Single thread.
 */
static void wait_gp(void)
{
	/* Read reader_gp before read futex */
	cmm_smp_rmb();
	if (uatomic_read(&rcu_gp.futex) != -1)
		return;
	while (futex_noasync(&rcu_gp.futex, FUTEX_WAIT, -1,
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

/*
 * Always called with rcu_registry lock held. Releases this lock between
 * iterations and grabs it again. Holds the lock when it returns.
 */
static void wait_for_readers(struct cds_list_head *input_readers,
			struct cds_list_head *cur_snap_readers,
			struct cds_list_head *qsreaders)
{
	unsigned int wait_loops = 0;
	struct rcu_reader *index, *tmp;

	/*
	 * Wait for each thread URCU_TLS(rcu_reader).ctr to either
	 * indicate quiescence (offline), or for them to observe the
	 * current rcu_gp.ctr value.
	 */
	for (;;) {
		if (wait_loops < RCU_QS_ACTIVE_ATTEMPTS)
			wait_loops++;
		if (wait_loops >= RCU_QS_ACTIVE_ATTEMPTS) {
			uatomic_set(&rcu_gp.futex, -1);
			/*
			 * Write futex before write waiting (the other side
			 * reads them in the opposite order).
			 */
			cmm_smp_wmb();
			cds_list_for_each_entry(index, input_readers, node) {
				_CMM_STORE_SHARED(index->waiting, 1);
			}
			/* Write futex before read reader_gp */
			cmm_smp_mb();
		}
		cds_list_for_each_entry_safe(index, tmp, input_readers, node) {
			switch (rcu_reader_state(&index->ctr)) {
			case RCU_READER_ACTIVE_CURRENT:
				if (cur_snap_readers) {
					cds_list_move(&index->node,
						cur_snap_readers);
					break;
				}
				/* Fall-through */
			case RCU_READER_INACTIVE:
				cds_list_move(&index->node, qsreaders);
				break;
			case RCU_READER_ACTIVE_OLD:
				/*
				 * Old snapshot. Leaving node in
				 * input_readers will make us busy-loop
				 * until the snapshot becomes current or
				 * the reader becomes inactive.
				 */
				break;
			}
		}

		if (cds_list_empty(input_readers)) {
			if (wait_loops >= RCU_QS_ACTIVE_ATTEMPTS) {
				/* Read reader_gp before write futex */
				cmm_smp_mb();
				uatomic_set(&rcu_gp.futex, 0);
			}
			break;
		} else {
			/* Temporarily unlock the registry lock. */
			mutex_unlock(&rcu_registry_lock);
			if (wait_loops >= RCU_QS_ACTIVE_ATTEMPTS) {
				wait_gp();
			} else {
#ifndef HAS_INCOHERENT_CACHES
				caa_cpu_relax();
#else /* #ifndef HAS_INCOHERENT_CACHES */
				cmm_smp_mb();
#endif /* #else #ifndef HAS_INCOHERENT_CACHES */
			}
			/* Re-lock the registry lock before the next loop. */
			mutex_lock(&rcu_registry_lock);
		}
	}
}

/*
 * Using a two-subphases algorithm for architectures with smaller than 64-bit
 * long-size to ensure we do not encounter an overflow bug.
 */

#if (CAA_BITS_PER_LONG < 64)
void synchronize_rcu(void)
{
	CDS_LIST_HEAD(cur_snap_readers);
	CDS_LIST_HEAD(qsreaders);
	unsigned long was_online;
	DEFINE_URCU_WAIT_NODE(wait, URCU_WAIT_WAITING);
	struct urcu_waiters waiters;

	was_online = rcu_read_ongoing();

	/* All threads should read qparity before accessing data structure
	 * where new ptr points to.  In the "then" case, rcu_thread_offline
	 * includes a memory barrier.
	 *
	 * Mark the writer thread offline to make sure we don't wait for
	 * our own quiescent state. This allows using synchronize_rcu()
	 * in threads registered as readers.
	 */
	if (was_online)
		rcu_thread_offline();
	else
		cmm_smp_mb();

	/*
	 * Add ourself to gp_waiters queue of threads awaiting to wait
	 * for a grace period. Proceed to perform the grace period only
	 * if we are the first thread added into the queue.
	 */
	if (urcu_wait_add(&gp_waiters, &wait) != 0) {
		/* Not first in queue: will be awakened by another thread. */
		urcu_adaptative_busy_wait(&wait);
		goto gp_end;
	}
	/* We won't need to wake ourself up */
	urcu_wait_set_state(&wait, URCU_WAIT_RUNNING);

	mutex_lock(&rcu_gp_lock);

	/*
	 * Move all waiters into our local queue.
	 */
	urcu_move_waiters(&waiters, &gp_waiters);

	mutex_lock(&rcu_registry_lock);

	if (cds_list_empty(&registry))
		goto out;

	/*
	 * Wait for readers to observe original parity or be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	wait_for_readers(&registry, &cur_snap_readers, &qsreaders);

	/*
	 * Must finish waiting for quiescent state for original parity
	 * before committing next rcu_gp.ctr update to memory. Failure
	 * to do so could result in the writer waiting forever while new
	 * readers are always accessing data (no progress).  Enforce
	 * compiler-order of load URCU_TLS(rcu_reader).ctr before store
	 * to rcu_gp.ctr.
	 */
	cmm_barrier();

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/* Switch parity: 0 -> 1, 1 -> 0 */
	CMM_STORE_SHARED(rcu_gp.ctr, rcu_gp.ctr ^ RCU_GP_CTR);

	/*
	 * Must commit rcu_gp.ctr update to memory before waiting for
	 * quiescent state. Failure to do so could result in the writer
	 * waiting forever while new readers are always accessing data
	 * (no progress). Enforce compiler-order of store to rcu_gp.ctr
	 * before load URCU_TLS(rcu_reader).ctr.
	 */
	cmm_barrier();

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/*
	 * Wait for readers to observe new parity or be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	wait_for_readers(&cur_snap_readers, NULL, &qsreaders);

	/*
	 * Put quiescent reader list back into registry.
	 */
	cds_list_splice(&qsreaders, &registry);
out:
	mutex_unlock(&rcu_registry_lock);
	mutex_unlock(&rcu_gp_lock);
	urcu_wake_all_waiters(&waiters);
gp_end:
	/*
	 * Finish waiting for reader threads before letting the old ptr being
	 * freed.
	 */
	if (was_online)
		rcu_thread_online();
	else
		cmm_smp_mb();
}
#else /* !(CAA_BITS_PER_LONG < 64) */
void synchronize_rcu(void)
{
	CDS_LIST_HEAD(qsreaders);
	unsigned long was_online;
	DEFINE_URCU_WAIT_NODE(wait, URCU_WAIT_WAITING);
	struct urcu_waiters waiters;

	was_online = rcu_read_ongoing();

	/*
	 * Mark the writer thread offline to make sure we don't wait for
	 * our own quiescent state. This allows using synchronize_rcu()
	 * in threads registered as readers.
	 */
	if (was_online)
		rcu_thread_offline();
	else
		cmm_smp_mb();

	/*
	 * Add ourself to gp_waiters queue of threads awaiting to wait
	 * for a grace period. Proceed to perform the grace period only
	 * if we are the first thread added into the queue.
	 */
	if (urcu_wait_add(&gp_waiters, &wait) != 0) {
		/* Not first in queue: will be awakened by another thread. */
		urcu_adaptative_busy_wait(&wait);
		goto gp_end;
	}
	/* We won't need to wake ourself up */
	urcu_wait_set_state(&wait, URCU_WAIT_RUNNING);

	mutex_lock(&rcu_gp_lock);

	/*
	 * Move all waiters into our local queue.
	 */
	urcu_move_waiters(&waiters, &gp_waiters);

	mutex_lock(&rcu_registry_lock);

	if (cds_list_empty(&registry))
		goto out;

	/* Increment current G.P. */
	CMM_STORE_SHARED(rcu_gp.ctr, rcu_gp.ctr + RCU_GP_CTR);

	/*
	 * Must commit rcu_gp.ctr update to memory before waiting for
	 * quiescent state. Failure to do so could result in the writer
	 * waiting forever while new readers are always accessing data
	 * (no progress). Enforce compiler-order of store to rcu_gp.ctr
	 * before load URCU_TLS(rcu_reader).ctr.
	 */
	cmm_barrier();

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/*
	 * Wait for readers to observe new count of be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	wait_for_readers(&registry, NULL, &qsreaders);

	/*
	 * Put quiescent reader list back into registry.
	 */
	cds_list_splice(&qsreaders, &registry);
out:
	mutex_unlock(&rcu_registry_lock);
	mutex_unlock(&rcu_gp_lock);
	urcu_wake_all_waiters(&waiters);
gp_end:
	if (was_online)
		rcu_thread_online();
	else
		cmm_smp_mb();
}
#endif  /* !(CAA_BITS_PER_LONG < 64) */

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void rcu_read_lock(void)
{
	_rcu_read_lock();
}

void rcu_read_unlock(void)
{
	_rcu_read_unlock();
}

int rcu_read_ongoing(void)
{
	return _rcu_read_ongoing();
}

void rcu_quiescent_state(void)
{
	_rcu_quiescent_state();
}

void rcu_thread_offline(void)
{
	_rcu_thread_offline();
}

void rcu_thread_online(void)
{
	_rcu_thread_online();
}

void rcu_register_thread(void)
{
	URCU_TLS(rcu_reader).tid = pthread_self();
	assert(URCU_TLS(rcu_reader).ctr == 0);

	mutex_lock(&rcu_registry_lock);
	cds_list_add(&URCU_TLS(rcu_reader).node, &registry);
	mutex_unlock(&rcu_registry_lock);
	_rcu_thread_online();
}

void rcu_unregister_thread(void)
{
	/*
	 * We have to make the thread offline otherwise we end up dealocking
	 * with a waiting writer.
	 */
	_rcu_thread_offline();
	mutex_lock(&rcu_registry_lock);
	cds_list_del(&URCU_TLS(rcu_reader).node);
	mutex_unlock(&rcu_registry_lock);
}

void rcu_exit(void)
{
	/*
	 * Assertion disabled because call_rcu threads are now rcu
	 * readers, and left running at exit.
	 * assert(cds_list_empty(&registry));
	 */
}

DEFINE_RCU_FLAVOR(rcu_flavor);

#include "urcu-call-rcu-impl.h"
#include "urcu-defer-impl.h"
