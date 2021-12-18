#ifndef _URCU_TESTS_CPUSET_H
#define _URCU_TESTS_CPUSET_H

/*
 * cpuset.h
 *
 * Userspace RCU library - test cpuset header
 *
 * Copyright 2009-2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#if defined(HAVE_SCHED_SETAFFINITY) || defined(HAVE_CPU_SET_T)	\
		|| defined(HAVE_CPU_ZERO) || defined(HAVE_CPU_SET)
# include <sched.h>
#endif

#ifndef HAVE_CPU_SET_T
typedef unsigned long cpu_set_t;
#endif

#ifndef HAVE_CPU_ZERO
# define CPU_ZERO(cpuset) do { *(cpuset) = 0; } while(0)
#endif

#ifndef HAVE_CPU_SET
# define CPU_SET(cpu, cpuset) do { *(cpuset) |= (1UL << (cpu)); } while(0)
#endif

#endif /* _URCU_TESTS_CPUSET_H */
