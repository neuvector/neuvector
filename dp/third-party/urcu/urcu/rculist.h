/*
 * Copyright (C) 2002 Free Software Foundation, Inc.
 * (originally part of the GNU C Library)
 * Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Conversion to RCU list.
 * Copyright (C) 2010 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef _URCU_RCULIST_H
#define _URCU_RCULIST_H

#include <urcu/list.h>
#include <urcu/arch.h>
#include <urcu-pointer.h>

/* Add new element at the head of the list. */
static inline
void cds_list_add_rcu(struct cds_list_head *newp, struct cds_list_head *head)
{
	newp->next = head->next;
	newp->prev = head;
	head->next->prev = newp;
	rcu_assign_pointer(head->next, newp);
}

/* Add new element at the tail of the list. */
static inline
void cds_list_add_tail_rcu(struct cds_list_head *newp,
		struct cds_list_head *head)
{
	newp->next = head;
	newp->prev = head->prev;
	rcu_assign_pointer(head->prev->next, newp);
	head->prev = newp;
}

/*
 * Replace an old entry atomically with respect to concurrent RCU
 * traversal. Mutual exclusion against concurrent updates is required
 * though.
 */
static inline
void cds_list_replace_rcu(struct cds_list_head *old, struct cds_list_head *_new)
{
	_new->next = old->next;
	_new->prev = old->prev;
	rcu_assign_pointer(_new->prev->next, _new);
	_new->next->prev = _new;
}

/* Remove element from list. */
static inline
void cds_list_del_rcu(struct cds_list_head *elem)
{
	elem->next->prev = elem->prev;
	CMM_STORE_SHARED(elem->prev->next, elem->next);
}

/*
 * Iteration through all elements of the list must be done while rcu_read_lock()
 * is held.
 */

/* Iterate forward over the elements of the list.  */
#define cds_list_for_each_rcu(pos, head) \
	for (pos = rcu_dereference((head)->next); pos != (head); \
		pos = rcu_dereference(pos->next))


/* Iterate through elements of the list. */
#define cds_list_for_each_entry_rcu(pos, head, member) \
	for (pos = cds_list_entry(rcu_dereference((head)->next), __typeof__(*pos), member); \
		&pos->member != (head); \
		pos = cds_list_entry(rcu_dereference(pos->member.next), __typeof__(*pos), member))

#endif	/* _URCU_RCULIST_H */
