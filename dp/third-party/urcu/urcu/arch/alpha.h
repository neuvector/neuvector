#ifndef _URCU_ARCH_ALPHA_H
#define _URCU_ARCH_ALPHA_H

/*
 * arch_alpha.h: trivial definitions for the Alpha architecture.
 *
 * Copyright (c) 2010 Paolo Bonzini <pbonzini@redhat.com>
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

#define cmm_mb()			__asm__ __volatile__ ("mb":::"memory")
#define cmm_wmb()			__asm__ __volatile__ ("wmb":::"memory")
#define cmm_read_barrier_depends()	__asm__ __volatile__ ("mb":::"memory")

typedef unsigned long long cycles_t;

static inline cycles_t caa_get_cycles (void)
{
	return 0;	/* not supported */
}

#ifdef __cplusplus
}
#endif

#include <urcu/arch/generic.h>

#endif /* _URCU_ARCH_ALPHA_H */
