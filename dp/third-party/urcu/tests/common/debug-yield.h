#ifndef URCU_TESTS_DEBUG_YIELD_H
#define URCU_TESTS_DEBUG_YIELD_H

/*
 * debug-yield.h
 *
 * Userspace RCU library tests - Debugging header
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

#include <sched.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define RCU_YIELD_READ 	(1 << 0)
#define RCU_YIELD_WRITE	(1 << 1)

/*
 * Updates with RCU_SIGNAL are much slower. Account this in the delay.
 */
#ifdef RCU_SIGNAL
/* maximum sleep delay, in us */
#define MAX_SLEEP 30000
#else
#define MAX_SLEEP 50
#endif

extern unsigned int rcu_yield_active;
extern DECLARE_URCU_TLS(unsigned int, rcu_rand_yield);

#ifdef DEBUG_YIELD
static inline void rcu_debug_yield_read(void)
{
	if (rcu_yield_active & RCU_YIELD_READ)
		if (rand_r(&URCU_TLS(rcu_rand_yield)) & 0x1)
			usleep(rand_r(&URCU_TLS(rcu_rand_yield)) % MAX_SLEEP);
}

static inline void rcu_debug_yield_write(void)
{
	if (rcu_yield_active & RCU_YIELD_WRITE)
		if (rand_r(&URCU_TLS(rcu_rand_yield)) & 0x1)
			usleep(rand_r(&URCU_TLS(rcu_rand_yield)) % MAX_SLEEP);
}

static inline void rcu_debug_yield_enable(unsigned int flags)
{
	rcu_yield_active |= flags;
}

static inline void rcu_debug_yield_disable(unsigned int flags)
{
	rcu_yield_active &= ~flags;
}

static inline void rcu_debug_yield_init(void)
{
	URCU_TLS(rcu_rand_yield) = time(NULL) ^ (unsigned long) pthread_self();
}
#else /* DEBUG_YIELD */
static inline void rcu_debug_yield_read(void)
{
}

static inline void rcu_debug_yield_write(void)
{
}

static inline void rcu_debug_yield_enable(unsigned int flags)
{
}

static inline void rcu_debug_yield_disable(unsigned int flags)
{
}

static inline void rcu_debug_yield_init(void)
{
}
#endif

#endif /* URCU_TESTS_DEBUG_YIELD_H */
