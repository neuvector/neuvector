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

#ifndef _URCU_RCUHLIST_H
#define _URCU_RCUHLIST_H

#include <urcu/hlist.h>
#include <urcu/arch.h>
#include <urcu-pointer.h>

/* Add new element at the head of the list. */
static inline
void cds_hlist_add_head_rcu(struct cds_hlist_node *newp,
		struct cds_hlist_head *head)
{
	newp->next = head->next;
	newp->prev = (struct cds_hlist_node *)head;
	if (head->next)
		head->next->prev = newp;
	rcu_assign_pointer(head->next, newp);
}

/* Remove element from list. */
static inline
void cds_hlist_del_rcu(struct cds_hlist_node *elem)
{
	if (elem->next)
		elem->next->prev = elem->prev;
	CMM_STORE_SHARED(elem->prev->next, elem->next);
}

/*
 * Iterate through elements of the list.
 * This must be done while rcu_read_lock() is held.
 */
#define cds_hlist_for_each_rcu(pos, head) \
	for (pos = rcu_dereference((head)->next); pos != NULL; \
		pos = rcu_dereference(pos->next))

/*
 * cds_hlist_for_each_entry_rcu takes 4 arguments, while the Linux
 * kernel API only takes 3.
 * We implement cds_hlist_for_each_entry_rcu_2() to follow the Linux
 * kernel APIs.
 */
#define cds_hlist_for_each_entry_rcu(entry, pos, head, member) \
	for (pos = rcu_dereference((head)->next), \
			entry = cds_hlist_entry(pos, __typeof__(*entry), member); \
		pos != NULL; \
		pos = rcu_dereference(pos->next), \
			entry = cds_hlist_entry(pos, __typeof__(*entry), member))

#define cds_hlist_for_each_entry_rcu_2(entry, head, member) \
	for (entry = cds_hlist_entry(rcu_dereference((head)->next), \
			__typeof__(*entry), member); \
		&entry->member != NULL; \
		entry = cds_hlist_entry(rcu_dereference(entry->member.next), \
			__typeof__(*entry), member))

#endif	/* _URCU_RCUHLIST_H */
