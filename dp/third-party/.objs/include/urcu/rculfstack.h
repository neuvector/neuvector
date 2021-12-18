#ifndef _URCU_RCULFSTACK_H
#define _URCU_RCULFSTACK_H

/*
 * rculfstack.h
 *
 * Userspace RCU library - Lock-Free RCU Stack
 *
 * Copyright 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CDS_LFS_RCU_DEPRECATED
#define CDS_LFS_RCU_DEPRECATED	\
	CDS_DEPRECATED("urcu/rculfstack.h is deprecated. Please use urcu/lfstack.h instead.")
#endif

struct cds_lfs_node_rcu {
	struct cds_lfs_node_rcu *next;
};

struct cds_lfs_stack_rcu {
	struct cds_lfs_node_rcu *head;
};

#ifdef _LGPL_SOURCE

#include <urcu/static/rculfstack.h>

static inline CDS_LFS_RCU_DEPRECATED
void cds_lfs_node_init_rcu(struct cds_lfs_node_rcu *node)
{
	_cds_lfs_node_init_rcu(node);
}

static inline
void cds_lfs_init_rcu(struct cds_lfs_stack_rcu *s)
{
	_cds_lfs_init_rcu(s);
}

static inline CDS_LFS_RCU_DEPRECATED
int cds_lfs_push_rcu(struct cds_lfs_stack_rcu *s,
			struct cds_lfs_node_rcu *node)
{
	return _cds_lfs_push_rcu(s, node);
}

static inline CDS_LFS_RCU_DEPRECATED
struct cds_lfs_node_rcu *cds_lfs_pop_rcu(struct cds_lfs_stack_rcu *s)
{
	return _cds_lfs_pop_rcu(s);
}

#else /* !_LGPL_SOURCE */

extern CDS_LFS_RCU_DEPRECATED
void cds_lfs_node_init_rcu(struct cds_lfs_node_rcu *node);
extern CDS_LFS_RCU_DEPRECATED
void cds_lfs_init_rcu(struct cds_lfs_stack_rcu *s);
extern CDS_LFS_RCU_DEPRECATED
int cds_lfs_push_rcu(struct cds_lfs_stack_rcu *s,
			struct cds_lfs_node_rcu *node);

/*
 * Should be called under rcu read lock critical section.
 *
 * The caller must wait for a grace period to pass before freeing the returned
 * node or modifying the cds_lfs_node_rcu structure.
 * Returns NULL if stack is empty.
 */
extern CDS_LFS_RCU_DEPRECATED
struct cds_lfs_node_rcu *cds_lfs_pop_rcu(struct cds_lfs_stack_rcu *s);

#endif /* !_LGPL_SOURCE */

#ifdef __cplusplus
}
#endif

#endif /* _URCU_RCULFSTACK_H */
