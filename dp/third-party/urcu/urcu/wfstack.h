#ifndef _URCU_WFSTACK_H
#define _URCU_WFSTACK_H

/*
 * urcu/wfstack.h
 *
 * Userspace RCU library - Stack with wait-free push, blocking traversal.
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

#include <pthread.h>
#include <assert.h>
#include <stdbool.h>
#include <urcu/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stack with wait-free push, blocking traversal.
 *
 * Stack implementing push, pop, pop_all operations, as well as iterator
 * on the stack head returned by pop_all.
 *
 * Wait-free operations: cds_wfs_push, __cds_wfs_pop_all, cds_wfs_empty,
 *                       cds_wfs_first.
 * Blocking operations: cds_wfs_pop, cds_wfs_pop_all, cds_wfs_next,
 *                      iteration on stack head returned by pop_all.
 *
 * Synchronization table:
 *
 * External synchronization techniques described in the API below is
 * required between pairs marked with "X". No external synchronization
 * required between pairs marked with "-".
 *
 *                      cds_wfs_push  __cds_wfs_pop  __cds_wfs_pop_all
 * cds_wfs_push               -              -                  -
 * __cds_wfs_pop              -              X                  X
 * __cds_wfs_pop_all          -              X                  -
 *
 * cds_wfs_pop and cds_wfs_pop_all use an internal mutex to provide
 * synchronization.
 */

#define CDS_WFS_WOULDBLOCK	((void *) -1UL)

enum cds_wfs_state {
	CDS_WFS_STATE_LAST =		(1U << 0),
};

/*
 * struct cds_wfs_node is returned by __cds_wfs_pop, and also used as
 * iterator on stack. It is not safe to dereference the node next
 * pointer when returned by __cds_wfs_pop_blocking.
 */
struct cds_wfs_node {
	struct cds_wfs_node *next;
};

/*
 * struct cds_wfs_head is returned by __cds_wfs_pop_all, and can be used
 * to begin iteration on the stack. "node" needs to be the first field of
 * cds_wfs_head, so the end-of-stack pointer value can be used for both
 * types.
 */
struct cds_wfs_head {
	struct cds_wfs_node node;
};

struct cds_wfs_stack {
	struct cds_wfs_head *head;
	pthread_mutex_t lock;
};

#ifdef _LGPL_SOURCE

#include <urcu/static/wfstack.h>

#define cds_wfs_node_init		_cds_wfs_node_init
#define cds_wfs_init			_cds_wfs_init
#define cds_wfs_empty			_cds_wfs_empty
#define cds_wfs_push			_cds_wfs_push

/* Locking performed internally */
#define cds_wfs_pop_blocking		_cds_wfs_pop_blocking
#define cds_wfs_pop_with_state_blocking	_cds_wfs_pop_with_state_blocking
#define cds_wfs_pop_all_blocking	_cds_wfs_pop_all_blocking

/*
 * For iteration on cds_wfs_head returned by __cds_wfs_pop_all or
 * cds_wfs_pop_all_blocking.
 */
#define cds_wfs_first			_cds_wfs_first
#define cds_wfs_next_blocking		_cds_wfs_next_blocking
#define cds_wfs_next_nonblocking	_cds_wfs_next_nonblocking

/* Pop locking with internal mutex */
#define cds_wfs_pop_lock		_cds_wfs_pop_lock
#define cds_wfs_pop_unlock		_cds_wfs_pop_unlock

/* Synchronization ensured by the caller. See synchronization table. */
#define __cds_wfs_pop_blocking		___cds_wfs_pop_blocking
#define __cds_wfs_pop_with_state_blocking	\
					___cds_wfs_pop_with_state_blocking
#define __cds_wfs_pop_nonblocking	___cds_wfs_pop_nonblocking
#define __cds_wfs_pop_with_state_nonblocking	\
					___cds_wfs_pop_with_state_nonblocking
#define __cds_wfs_pop_all		___cds_wfs_pop_all

#else /* !_LGPL_SOURCE */

/*
 * cds_wfs_node_init: initialize wait-free stack node.
 */
extern void cds_wfs_node_init(struct cds_wfs_node *node);

/*
 * cds_wfs_init: initialize wait-free stack.
 */
extern void cds_wfs_init(struct cds_wfs_stack *s);

/*
 * cds_wfs_empty: return whether wait-free stack is empty.
 *
 * No memory barrier is issued. No mutual exclusion is required.
 */
extern bool cds_wfs_empty(struct cds_wfs_stack *s);

/*
 * cds_wfs_push: push a node into the stack.
 *
 * Issues a full memory barrier before push. No mutual exclusion is
 * required.
 *
 * Returns 0 if the stack was empty prior to adding the node.
 * Returns non-zero otherwise.
 */
extern int cds_wfs_push(struct cds_wfs_stack *s, struct cds_wfs_node *node);

/*
 * cds_wfs_pop_blocking: pop a node from the stack.
 *
 * Calls __cds_wfs_pop_blocking with an internal pop mutex held.
 */
extern struct cds_wfs_node *cds_wfs_pop_blocking(struct cds_wfs_stack *s);

/*
 * cds_wfs_pop_with_state_blocking: pop a node from the stack, with state.
 *
 * Same as cds_wfs_pop_blocking, but stores whether the stack was
 * empty into state (CDS_WFS_STATE_LAST).
 */
extern struct cds_wfs_node *
	cds_wfs_pop_with_state_blocking(struct cds_wfs_stack *s, int *state);

/*
 * cds_wfs_pop_all_blocking: pop all nodes from a stack.
 *
 * Calls __cds_wfs_pop_all with an internal pop mutex held.
 */
extern struct cds_wfs_head *cds_wfs_pop_all_blocking(struct cds_wfs_stack *s);

/*
 * cds_wfs_first: get first node of a popped stack.
 *
 * Content written into the node before enqueue is guaranteed to be
 * consistent, but no other memory ordering is ensured.
 *
 * Used by for-like iteration macros in urcu/wfstack.h:
 * cds_wfs_for_each_blocking()
 * cds_wfs_for_each_blocking_safe()
 *
 * Returns NULL if popped stack is empty, top stack node otherwise.
 */
extern struct cds_wfs_node *cds_wfs_first(struct cds_wfs_head *head);

/*
 * cds_wfs_next_blocking: get next node of a popped stack.
 *
 * Content written into the node before enqueue is guaranteed to be
 * consistent, but no other memory ordering is ensured.
 *
 * Used by for-like iteration macros in urcu/wfstack.h:
 * cds_wfs_for_each_blocking()
 * cds_wfs_for_each_blocking_safe()
 *
 * Returns NULL if reached end of popped stack, non-NULL next stack
 * node otherwise.
 */
extern struct cds_wfs_node *cds_wfs_next_blocking(struct cds_wfs_node *node);

/*
 * cds_wfs_next_nonblocking: get next node of a popped stack.
 *
 * Same as cds_wfs_next_blocking, but returns CDS_WFS_WOULDBLOCK if it
 * needs to block.
 */
extern struct cds_wfs_node *cds_wfs_next_nonblocking(struct cds_wfs_node *node);

/*
 * cds_wfs_pop_lock: lock stack pop-protection mutex.
 */
extern void cds_wfs_pop_lock(struct cds_wfs_stack *s);

/*
 * cds_wfs_pop_unlock: unlock stack pop-protection mutex.
 */
extern void cds_wfs_pop_unlock(struct cds_wfs_stack *s);

/*
 * __cds_wfs_pop_blocking: pop a node from the stack.
 *
 * Returns NULL if stack is empty.
 *
 * __cds_wfs_pop_blocking needs to be synchronized using one of the
 * following techniques:
 *
 * 1) Calling __cds_wfs_pop_blocking under rcu read lock critical
 *    section. The caller must wait for a grace period to pass before
 *    freeing the returned node or modifying the cds_wfs_node structure.
 * 2) Using mutual exclusion (e.g. mutexes) to protect
 *     __cds_wfs_pop_blocking and __cds_wfs_pop_all callers.
 * 3) Ensuring that only ONE thread can call __cds_wfs_pop_blocking()
 *    and __cds_wfs_pop_all(). (multi-provider/single-consumer scheme).
 */
extern struct cds_wfs_node *__cds_wfs_pop_blocking(struct cds_wfs_stack *s);

/*
 * __cds_wfs_pop_with_state_blocking: pop a node from the stack, with state.
 *
 * Same as __cds_wfs_pop_blocking, but stores whether the stack was
 * empty into state (CDS_WFS_STATE_LAST).
 */
extern struct cds_wfs_node *
	__cds_wfs_pop_with_state_blocking(struct cds_wfs_stack *s, int *state);

/*
 * __cds_wfs_pop_nonblocking: pop a node from the stack.
 *
 * Same as __cds_wfs_pop_blocking, but returns CDS_WFS_WOULDBLOCK if
 * it needs to block.
 */
extern struct cds_wfs_node *__cds_wfs_pop_nonblocking(struct cds_wfs_stack *s);

/*
 * __cds_wfs_pop_with_state_nonblocking: pop a node from the stack, with state.
 *
 * Same as __cds_wfs_pop_nonblocking, but stores whether the stack was
 * empty into state (CDS_WFS_STATE_LAST).
 */
extern struct cds_wfs_node *
	__cds_wfs_pop_with_state_nonblocking(struct cds_wfs_stack *s,
		int *state);

/*
 * __cds_wfs_pop_all: pop all nodes from a stack.
 *
 * __cds_wfs_pop_all does not require any synchronization with other
 * push, nor with other __cds_wfs_pop_all, but requires synchronization
 * matching the technique used to synchronize __cds_wfs_pop_blocking:
 *
 * 1) If __cds_wfs_pop_blocking is called under rcu read lock critical
 *    section, both __cds_wfs_pop_blocking and cds_wfs_pop_all callers
 *    must wait for a grace period to pass before freeing the returned
 *    node or modifying the cds_wfs_node structure. However, no RCU
 *    read-side critical section is needed around __cds_wfs_pop_all.
 * 2) Using mutual exclusion (e.g. mutexes) to protect
 *     __cds_wfs_pop_blocking and __cds_wfs_pop_all callers.
 * 3) Ensuring that only ONE thread can call __cds_wfs_pop_blocking()
 *    and __cds_wfs_pop_all(). (multi-provider/single-consumer scheme).
 */
extern struct cds_wfs_head *__cds_wfs_pop_all(struct cds_wfs_stack *s);

#endif /* !_LGPL_SOURCE */

#ifdef __cplusplus
}
#endif

/*
 * cds_wfs_for_each_blocking: Iterate over all nodes returned by
 * __cds_wfs_pop_all().
 * @head: head of the queue (struct cds_wfs_head pointer).
 * @node: iterator (struct cds_wfs_node pointer).
 *
 * Content written into each node before enqueue is guaranteed to be
 * consistent, but no other memory ordering is ensured.
 */
#define cds_wfs_for_each_blocking(head, node)			\
	for (node = cds_wfs_first(head);			\
		node != NULL;					\
		node = cds_wfs_next_blocking(node))

/*
 * cds_wfs_for_each_blocking_safe: Iterate over all nodes returned by
 * __cds_wfs_pop_all(). Safe against deletion.
 * @head: head of the queue (struct cds_wfs_head pointer).
 * @node: iterator (struct cds_wfs_node pointer).
 * @n: struct cds_wfs_node pointer holding the next pointer (used
 *     internally).
 *
 * Content written into each node before enqueue is guaranteed to be
 * consistent, but no other memory ordering is ensured.
 */
#define cds_wfs_for_each_blocking_safe(head, node, n)			   \
	for (node = cds_wfs_first(head),				   \
			n = (node ? cds_wfs_next_blocking(node) : NULL);   \
		node != NULL;						   \
		node = n, n = (node ? cds_wfs_next_blocking(node) : NULL))

#endif /* _URCU_WFSTACK_H */
