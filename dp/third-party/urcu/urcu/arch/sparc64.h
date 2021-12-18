#ifndef _URCU_ARCH_SPARC64_H
#define _URCU_ARCH_SPARC64_H

/*
 * arch_sparc64.h: trivial definitions for the Sparc64 architecture.
 *
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

#include <urcu/compiler.h>
#include <urcu/config.h>

#ifdef __cplusplus
extern "C" {
#endif 

#define CAA_CACHE_LINE_SIZE	256

/*
 * Inspired from the Linux kernel. Workaround Spitfire bug #51.
 */
#define membar_safe(type)			\
__asm__ __volatile__("ba,pt %%xcc, 1f\n\t"	\
		     "membar " type "\n"	\
		     "1:\n"			\
		     : : : "memory")

#define cmm_mb()	membar_safe("#LoadLoad | #LoadStore | #StoreStore | #StoreLoad")
#define cmm_rmb()	membar_safe("#LoadLoad")
#define cmm_wmb()	membar_safe("#StoreStore")

typedef unsigned long long cycles_t;

static inline cycles_t caa_get_cycles (void)
{
	return 0;	/* unimplemented */
}

#ifdef __cplusplus 
}
#endif

#include <urcu/arch/generic.h>

#endif /* _URCU_ARCH_SPARC64_H */
