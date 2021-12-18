#ifndef _URCU_ARCH_UNKNOWN_H
#define _URCU_ARCH_UNKNOWN_H

/*
 * arch_unknown.h: #error to prevent build on unknown architectures.
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

/* See configure.ac for the list of recognized architectures.  */
#error "Cannot build: unrecognized architecture detected."

#endif /* _URCU_ARCH_UNKNOWN_H */
