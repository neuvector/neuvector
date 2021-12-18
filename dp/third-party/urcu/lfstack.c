/*
 * lfstack.c
 *
 * Userspace RCU library - Lock-Free Stack
 *
 * Copyright 2010-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#undef _LGPL_SOURCE
#include "urcu/lfstack.h"
#define _LGPL_SOURCE
#include "urcu/static/lfstack.h"

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void cds_lfs_node_init(struct cds_lfs_node *node)
{
	_cds_lfs_node_init(node);
}

void cds_lfs_init(struct cds_lfs_stack *s)
{
	_cds_lfs_init(s);
}

bool cds_lfs_empty(struct cds_lfs_stack *s)
{
	return _cds_lfs_empty(s);
}

bool cds_lfs_push(struct cds_lfs_stack *s, struct cds_lfs_node *node)
{
	return _cds_lfs_push(s, node);
}

struct cds_lfs_node *cds_lfs_pop_blocking(struct cds_lfs_stack *s)
{
	return _cds_lfs_pop_blocking(s);
}

struct cds_lfs_head *cds_lfs_pop_all_blocking(struct cds_lfs_stack *s)
{
	return _cds_lfs_pop_all_blocking(s);
}

void cds_lfs_pop_lock(struct cds_lfs_stack *s)
{
	_cds_lfs_pop_lock(s);
}

void cds_lfs_pop_unlock(struct cds_lfs_stack *s)
{
	_cds_lfs_pop_unlock(s);
}

struct cds_lfs_node *__cds_lfs_pop(struct cds_lfs_stack *s)
{
	return ___cds_lfs_pop(s);
}

struct cds_lfs_head *__cds_lfs_pop_all(struct cds_lfs_stack *s)
{
	return ___cds_lfs_pop_all(s);
}
