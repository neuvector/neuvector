#ifndef _URCU_QSBR_STATIC_H
#define _URCU_QSBR_STATIC_H

/*
 * urcu-qsbr-static.h
 *
 * Userspace RCU QSBR header.
 *
 * TO BE INCLUDED ONLY IN CODE THAT IS TO BE RECOMPILED ON EACH LIBURCU
 * RELEASE. See urcu.h for linking dynamically with the userspace rcu library.
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
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>

#include <urcu/compiler.h>
#include <urcu/arch.h>
#include <urcu/system.h>
#include <urcu/uatomic.h>
#include <urcu/list.h>
#include <urcu/futex.h>
#include <urcu/tls-compat.h>

#ifdef __cplusplus
extern "C" {
#endif 

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

enum rcu_state {
	RCU_READER_ACTIVE_CURRENT,
	RCU_READER_ACTIVE_OLD,
	RCU_READER_INACTIVE,
};

#define RCU_GP_ONLINE		(1UL << 0)
#define RCU_GP_CTR		(1UL << 1)

struct rcu_gp {
	/*
	 * Global quiescent period counter with low-order bits unused.
	 * Using a int rather than a char to eliminate false register
	 * dependencies causing stalls on some architectures.
	 */
	unsigned long ctr;

	int32_t futex;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

extern struct rcu_gp rcu_gp;

struct rcu_reader {
	/* Data used by both reader and synchronize_rcu() */
	unsigned long ctr;
	/* Data used for registry */
	struct cds_list_head node __attribute__((aligned(CAA_CACHE_LINE_SIZE)));
	int waiting;
	pthread_t tid;
};

extern DECLARE_URCU_TLS(struct rcu_reader, rcu_reader);

/*
 * Wake-up waiting synchronize_rcu(). Called from many concurrent threads.
 */
static inline void wake_up_gp(void)
{
	if (caa_unlikely(_CMM_LOAD_SHARED(URCU_TLS(rcu_reader).waiting))) {
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader).waiting, 0);
		cmm_smp_mb();
		if (uatomic_read(&rcu_gp.futex) != -1)
			return;
		uatomic_set(&rcu_gp.futex, 0);
		/*
		 * Ignoring return value until we can make this function
		 * return something (because urcu_die() is not publicly
		 * exposed).
		 */
		(void) futex_noasync(&rcu_gp.futex, FUTEX_WAKE, 1,
				NULL, NULL, 0);
	}
}

static inline enum rcu_state rcu_reader_state(unsigned long *ctr)
{
	unsigned long v;

	v = CMM_LOAD_SHARED(*ctr);
	if (!v)
		return RCU_READER_INACTIVE;
	if (v == rcu_gp.ctr)
		return RCU_READER_ACTIVE_CURRENT;
	return RCU_READER_ACTIVE_OLD;
}

/*
 * Enter an RCU read-side critical section.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline void _rcu_read_lock(void)
{
	rcu_assert(URCU_TLS(rcu_reader).ctr);
}

/*
 * Exit an RCU read-side critical section.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline void _rcu_read_unlock(void)
{
}

/*
 * Returns whether within a RCU read-side critical section.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline int _rcu_read_ongoing(void)
{
	return URCU_TLS(rcu_reader).ctr;
}

/*
 * This is a helper function for _rcu_quiescent_state().
 * The first cmm_smp_mb() ensures memory accesses in the prior read-side
 * critical sections are not reordered with store to
 * URCU_TLS(rcu_reader).ctr, and ensures that mutexes held within an
 * offline section that would happen to end with this
 * rcu_quiescent_state() call are not reordered with
 * store to URCU_TLS(rcu_reader).ctr.
 */
static inline void _rcu_quiescent_state_update_and_wakeup(unsigned long gp_ctr)
{
	cmm_smp_mb();
	_CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, gp_ctr);
	cmm_smp_mb();	/* write URCU_TLS(rcu_reader).ctr before read futex */
	wake_up_gp();
	cmm_smp_mb();
}

/*
 * Inform RCU of a quiescent state.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 *
 * We skip the memory barriers and gp store if our local ctr already
 * matches the global rcu_gp.ctr value: this is OK because a prior
 * _rcu_quiescent_state() or _rcu_thread_online() already updated it
 * within our thread, so we have no quiescent state to report.
 */
static inline void _rcu_quiescent_state(void)
{
	unsigned long gp_ctr;

	if ((gp_ctr = CMM_LOAD_SHARED(rcu_gp.ctr)) == URCU_TLS(rcu_reader).ctr)
		return;
	_rcu_quiescent_state_update_and_wakeup(gp_ctr);
}

/*
 * Take a thread offline, prohibiting it from entering further RCU
 * read-side critical sections.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline void _rcu_thread_offline(void)
{
	cmm_smp_mb();
	CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, 0);
	cmm_smp_mb();	/* write URCU_TLS(rcu_reader).ctr before read futex */
	wake_up_gp();
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
}

/*
 * Bring a thread online, allowing it to once again enter RCU
 * read-side critical sections.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline void _rcu_thread_online(void)
{
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
	_CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, CMM_LOAD_SHARED(rcu_gp.ctr));
	cmm_smp_mb();
}

#ifdef __cplusplus 
}
#endif

#endif /* _URCU_QSBR_STATIC_H */
