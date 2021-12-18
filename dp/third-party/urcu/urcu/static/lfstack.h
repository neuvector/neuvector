#ifndef _URCU_STATIC_LFSTACK_H
#define _URCU_STATIC_LFSTACK_H

/*
 * urcu/static/lfstack.h
 *
 * Userspace RCU library - Lock-Free Stack
 *
 * Copyright 2010-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * TO BE INCLUDED ONLY IN LGPL-COMPATIBLE CODE. See urcu/lfstack.h for
 * linking dynamically with the userspace rcu library.
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

#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <urcu/uatomic.h>
#include <urcu-pointer.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Lock-free stack.
 *
 * Stack implementing push, pop, pop_all operations, as well as iterator
 * on the stack head returned by pop_all.
 *
 * Synchronization table:
 *
 * External synchronization techniques described in the API below is
 * required between pairs marked with "X". No external synchronization
 * required between pairs marked with "-".
 *
 *                      cds_lfs_push  __cds_lfs_pop  __cds_lfs_pop_all
 * cds_lfs_push               -              -                  -
 * __cds_lfs_pop              -              X                  X
 * __cds_lfs_pop_all          -              X                  -
 *
 * cds_lfs_pop_blocking and cds_lfs_pop_all_blocking use an internal
 * mutex to provide synchronization.
 */

/*
 * cds_lfs_node_init: initialize lock-free stack node.
 */
static inline
void _cds_lfs_node_init(struct cds_lfs_node *node)
{
}

/*
 * cds_lfs_init: initialize lock-free stack.
 */
static inline
void _cds_lfs_init(struct cds_lfs_stack *s)
{
        int ret;

	s->head = NULL;
	ret = pthread_mutex_init(&s->lock, NULL);
	assert(!ret);
}

static inline
bool ___cds_lfs_empty_head(struct cds_lfs_head *head)
{
	return head == NULL;
}

/*
 * cds_lfs_empty: return whether lock-free stack is empty.
 *
 * No memory barrier is issued. No mutual exclusion is required.
 */
static inline
bool _cds_lfs_empty(struct cds_lfs_stack *s)
{
	return ___cds_lfs_empty_head(CMM_LOAD_SHARED(s->head));
}

/*
 * cds_lfs_push: push a node into the stack.
 *
 * Does not require any synchronization with other push nor pop.
 *
 * Lock-free stack push is not subject to ABA problem, so no need to
 * take the RCU read-side lock. Even if "head" changes between two
 * uatomic_cmpxchg() invocations here (being popped, and then pushed
 * again by one or more concurrent threads), the second
 * uatomic_cmpxchg() invocation only cares about pushing a new entry at
 * the head of the stack, ensuring consistency by making sure the new
 * node->next is the same pointer value as the value replaced as head.
 * It does not care about the content of the actual next node, so it can
 * very well be reallocated between the two uatomic_cmpxchg().
 *
 * We take the approach of expecting the stack to be usually empty, so
 * we first try an initial uatomic_cmpxchg() on a NULL old_head, and
 * retry if the old head was non-NULL (the value read by the first
 * uatomic_cmpxchg() is used as old head for the following loop). The
 * upside of this scheme is to minimize the amount of cacheline traffic,
 * always performing an exclusive cacheline access, rather than doing
 * non-exclusive followed by exclusive cacheline access (which would be
 * required if we first read the old head value). This design decision
 * might be revisited after more thorough benchmarking on various
 * platforms.
 *
 * Returns 0 if the stack was empty prior to adding the node.
 * Returns non-zero otherwise.
 */
static inline
bool _cds_lfs_push(struct cds_lfs_stack *s,
		  struct cds_lfs_node *node)
{
	struct cds_lfs_head *head = NULL;
	struct cds_lfs_head *new_head =
		caa_container_of(node, struct cds_lfs_head, node);

	for (;;) {
		struct cds_lfs_head *old_head = head;

		/*
		 * node->next is still private at this point, no need to
		 * perform a _CMM_STORE_SHARED().
		 */
		node->next = &head->node;
		/*
		 * uatomic_cmpxchg() implicit memory barrier orders earlier
		 * stores to node before publication.
		 */
		head = uatomic_cmpxchg(&s->head, old_head, new_head);
		if (old_head == head)
			break;
	}
	return !___cds_lfs_empty_head(head);
}

/*
 * __cds_lfs_pop: pop a node from the stack.
 *
 * Returns NULL if stack is empty.
 *
 * __cds_lfs_pop needs to be synchronized using one of the following
 * techniques:
 *
 * 1) Calling __cds_lfs_pop under rcu read lock critical section. The
 *    caller must wait for a grace period to pass before freeing the
 *    returned node or modifying the cds_lfs_node structure.
 * 2) Using mutual exclusion (e.g. mutexes) to protect __cds_lfs_pop
 *    and __cds_lfs_pop_all callers.
 * 3) Ensuring that only ONE thread can call __cds_lfs_pop() and
 *    __cds_lfs_pop_all(). (multi-provider/single-consumer scheme).
 */
static inline
struct cds_lfs_node *___cds_lfs_pop(struct cds_lfs_stack *s)
{
	for (;;) {
		struct cds_lfs_head *head, *next_head;
		struct cds_lfs_node *next;

		head = _CMM_LOAD_SHARED(s->head);
		if (___cds_lfs_empty_head(head))
			return NULL;	/* Empty stack */

		/*
		 * Read head before head->next. Matches the implicit
		 * memory barrier before uatomic_cmpxchg() in
		 * cds_lfs_push.
		 */
		cmm_smp_read_barrier_depends();
		next = _CMM_LOAD_SHARED(head->node.next);
		next_head = caa_container_of(next,
				struct cds_lfs_head, node);
		if (uatomic_cmpxchg(&s->head, head, next_head) == head)
			return &head->node;
		/* busy-loop if head changed under us */
	}
}

/*
 * __cds_lfs_pop_all: pop all nodes from a stack.
 *
 * __cds_lfs_pop_all does not require any synchronization with other
 * push, nor with other __cds_lfs_pop_all, but requires synchronization
 * matching the technique used to synchronize __cds_lfs_pop:
 *
 * 1) If __cds_lfs_pop is called under rcu read lock critical section,
 *    both __cds_lfs_pop and cds_lfs_pop_all callers must wait for a
 *    grace period to pass before freeing the returned node or modifying
 *    the cds_lfs_node structure. However, no RCU read-side critical
 *    section is needed around __cds_lfs_pop_all.
 * 2) Using mutual exclusion (e.g. mutexes) to protect __cds_lfs_pop and
 *    __cds_lfs_pop_all callers.
 * 3) Ensuring that only ONE thread can call __cds_lfs_pop() and
 *    __cds_lfs_pop_all(). (multi-provider/single-consumer scheme).
 */
static inline
struct cds_lfs_head *___cds_lfs_pop_all(struct cds_lfs_stack *s)
{
	/*
	 * Implicit memory barrier after uatomic_xchg() matches implicit
	 * memory barrier before uatomic_cmpxchg() in cds_lfs_push. It
	 * ensures that all nodes of the returned list are consistent.
	 * There is no need to issue memory barriers when iterating on
	 * the returned list, because the full memory barrier issued
	 * prior to each uatomic_cmpxchg, which each write to head, are
	 * taking care to order writes to each node prior to the full
	 * memory barrier after this uatomic_xchg().
	 */
	return uatomic_xchg(&s->head, NULL);
}

/*
 * cds_lfs_pop_lock: lock stack pop-protection mutex.
 */
static inline void _cds_lfs_pop_lock(struct cds_lfs_stack *s)
{
	int ret;

	ret = pthread_mutex_lock(&s->lock);
	assert(!ret);
}

/*
 * cds_lfs_pop_unlock: unlock stack pop-protection mutex.
 */
static inline void _cds_lfs_pop_unlock(struct cds_lfs_stack *s)
{
	int ret;

	ret = pthread_mutex_unlock(&s->lock);
	assert(!ret);
}

/*
 * Call __cds_lfs_pop with an internal pop mutex held.
 */
static inline
struct cds_lfs_node *
_cds_lfs_pop_blocking(struct cds_lfs_stack *s)
{
	struct cds_lfs_node *retnode;

	_cds_lfs_pop_lock(s);
	retnode = ___cds_lfs_pop(s);
	_cds_lfs_pop_unlock(s);
	return retnode;
}

/*
 * Call __cds_lfs_pop_all with an internal pop mutex held.
 */
static inline
struct cds_lfs_head *
_cds_lfs_pop_all_blocking(struct cds_lfs_stack *s)
{
	struct cds_lfs_head *rethead;

	_cds_lfs_pop_lock(s);
	rethead = ___cds_lfs_pop_all(s);
	_cds_lfs_pop_unlock(s);
	return rethead;
}

#ifdef __cplusplus
}
#endif

#endif /* _URCU_STATIC_LFSTACK_H */
