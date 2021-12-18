#ifndef _URCU_DIE_H
#define _URCU_DIE_H

/*
 * urcu-die.h
 *
 * Userspace RCU library unrecoverable error handling
 *
 * Copyright (c) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define urcu_die(cause)								\
do {										\
	fprintf(stderr, "(" __FILE__ ":%s@%u) Unrecoverable error: %s\n",	\
		__func__, __LINE__, strerror(cause));				\
	abort();								\
} while (0)

#endif /* _URCU_DIE_H */
