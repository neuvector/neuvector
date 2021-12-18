#ifndef _URCU_ARCH_GCC_H
#define _URCU_ARCH_GCC_H

/*
 * arch_gcc.h: trivial definitions for architectures using gcc __sync_
 *
 * Copyright (c) 2010 Paul E. McKenney, IBM Corporation.
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

#include <stdlib.h>
#include <sys/time.h>

typedef unsigned long long cycles_t;

static inline cycles_t caa_get_cycles (void)
{
	cycles_t thetime;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		return 0;
	thetime = ((cycles_t)tv.tv_sec) * 1000000ULL + ((cycles_t)tv.tv_usec);
	return (cycles_t)thetime;
}

#ifdef __cplusplus 
}
#endif

#include <urcu/arch/generic.h>

#endif /* _URCU_ARCH_GCC_H */
