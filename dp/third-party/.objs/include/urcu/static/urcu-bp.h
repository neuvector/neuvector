#ifndef _URCU_BP_STATIC_H
#define _URCU_BP_STATIC_H

/*
 * urcu-bp-static.h
 *
 * Userspace RCU header.
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
#include <unistd.h>

#include <urcu/compiler.h>
#include <urcu/arch.h>
#include <urcu/system.h>
#include <urcu/uatomic.h>
#include <urcu/list.h>
#include <urcu/tls-compat.h>

/*
 * This code section can only be included in LGPL 2.1 compatible source code.
 * See below for the function call wrappers which can be used in code meant to
 * be only linked with the Userspace RCU library. This comes with a small
 * performance degradation on the read-side due to the added function calls.
 * This is required to permit relinking with newer versions of the library.
 */

#ifdef __cplusplus
extern "C" {
#endif

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

/*
 * The trick here is that RCU_GP_CTR_PHASE must be a multiple of 8 so we can use a
 * full 8-bits, 16-bits or 32-bits bitmask for the lower order bits.
 */
#define RCU_GP_COUNT		(1UL << 0)
/* Use the amount of bits equal to half of the architecture long size */
#define RCU_GP_CTR_PHASE		(1UL << (sizeof(long) << 2))
#define RCU_GP_CTR_NEST_MASK	(RCU_GP_CTR_PHASE - 1)

/*
 * Used internally by _rcu_read_lock.
 */
extern void rcu_bp_register(void);

struct rcu_gp {
	/*
	 * Global grace period counter.
	 * Contains the current RCU_GP_CTR_PHASE.
	 * Also has a RCU_GP_COUNT of 1, to accelerate the reader fast path.
	 * Written to only by writer with mutex taken.
	 * Read by both writer and readers.
	 */
	unsigned long ctr;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

extern struct rcu_gp rcu_gp;

struct rcu_reader {
	/* Data used by both reader and synchronize_rcu() */
	unsigned long ctr;
	/* Data used for registry */
	struct cds_list_head node __attribute__((aligned(CAA_CACHE_LINE_SIZE)));
	pthread_t tid;
	int alloc;	/* registry entry allocated */
};

/*
 * Bulletproof version keeps a pointer to a registry not part of the TLS.
 * Adds a pointer dereference on the read-side, but won't require to unregister
 * the reader thread.
 */
extern DECLARE_URCU_TLS(struct rcu_reader *, rcu_reader);

static inline enum rcu_state rcu_reader_state(unsigned long *ctr)
{
	unsigned long v;

	if (ctr == NULL)
		return RCU_READER_INACTIVE;
	/*
	 * Make sure both tests below are done on the same version of *value
	 * to insure consistency.
	 */
	v = CMM_LOAD_SHARED(*ctr);
	if (!(v & RCU_GP_CTR_NEST_MASK))
		return RCU_READER_INACTIVE;
	if (!((v ^ rcu_gp.ctr) & RCU_GP_CTR_PHASE))
		return RCU_READER_ACTIVE_CURRENT;
	return RCU_READER_ACTIVE_OLD;
}

/*
 * Helper for _rcu_read_lock().  The format of rcu_gp.ctr (as well as
 * the per-thread rcu_reader.ctr) has the upper bits containing a count of
 * _rcu_read_lock() nesting, and a lower-order bit that contains either zero
 * or RCU_GP_CTR_PHASE.  The smp_mb_slave() ensures that the accesses in
 * _rcu_read_lock() happen before the subsequent read-side critical section.
 */
static inline void _rcu_read_lock_update(unsigned long tmp)
{
	if (caa_likely(!(tmp & RCU_GP_CTR_NEST_MASK))) {
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader)->ctr, _CMM_LOAD_SHARED(rcu_gp.ctr));
		cmm_smp_mb();
	} else
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader)->ctr, tmp + RCU_GP_COUNT);
}

/*
 * Enter an RCU read-side critical section.
 *
 * The first cmm_barrier() call ensures that the compiler does not reorder
 * the body of _rcu_read_lock() with a mutex.
 *
 * This function and its helper are both less than 10 lines long.  The
 * intent is that this function meets the 10-line criterion in LGPL,
 * allowing this function to be invoked directly from non-LGPL code.
 */
static inline void _rcu_read_lock(void)
{
	unsigned long tmp;

	if (caa_unlikely(!URCU_TLS(rcu_reader)))
		rcu_bp_register(); /* If not yet registered. */
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
	tmp = URCU_TLS(rcu_reader)->ctr;
	_rcu_read_lock_update(tmp);
}

/*
 * Exit an RCU read-side critical section.  This function is less than
 * 10 lines of code, and is intended to be usable by non-LGPL code, as
 * called out in LGPL.
 */
static inline void _rcu_read_unlock(void)
{
	/*
	 * Finish using rcu before decrementing the pointer.
	 */
	cmm_smp_mb();
	_CMM_STORE_SHARED(URCU_TLS(rcu_reader)->ctr, URCU_TLS(rcu_reader)->ctr - RCU_GP_COUNT);
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
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
	if (caa_unlikely(!URCU_TLS(rcu_reader)))
		rcu_bp_register(); /* If not yet registered. */
	return URCU_TLS(rcu_reader)->ctr & RCU_GP_CTR_NEST_MASK;
}

#ifdef __cplusplus 
}
#endif

#endif /* _URCU_BP_STATIC_H */
