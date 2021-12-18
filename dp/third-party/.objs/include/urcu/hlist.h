#ifndef _KCOMPAT_HLIST_H
#define _KCOMPAT_HLIST_H

/*
 * Kernel sourcecode compatible lightweight single pointer list head useful
 * for implementing hash tables
 *
 * Copyright (C) 2009 Novell Inc.
 *
 * Author: Jan Blunck <jblunck@suse.de>
 *
 * Copyright (C) 2010-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free  Software Foundation.
 */

#include <stddef.h>

struct cds_hlist_head {
	struct cds_hlist_node *next;
};

struct cds_hlist_node {
	struct cds_hlist_node *next, *prev;
};

/* Initialize a new list head. */
static inline
void CDS_INIT_HLIST_HEAD(struct cds_hlist_head *ptr)
{
	ptr->next = NULL;
}

#define CDS_HLIST_HEAD(name) \
	struct cds_hlist_head name = { NULL }

#define CDS_HLIST_HEAD_INIT(name) \
	{ .next = NULL }

/* Get typed element from list at a given position. */
#define cds_hlist_entry(ptr, type, member) \
	((type *) ((char *) (ptr) - (unsigned long) (&((type *) 0)->member)))

/* Add new element at the head of the list. */
static inline
void cds_hlist_add_head(struct cds_hlist_node *newp,
		struct cds_hlist_head *head)
{
	if (head->next)
		head->next->prev = newp;
	newp->next = head->next;
	newp->prev = (struct cds_hlist_node *) head;
	head->next = newp;
}

/* Remove element from list. */
static inline
void cds_hlist_del(struct cds_hlist_node *elem)
{
	if (elem->next)
		elem->next->prev = elem->prev;
	elem->prev->next = elem->next;
}

#define cds_hlist_for_each(pos, head) \
	for (pos = (head)->next; pos != NULL; pos = pos->next)

#define cds_hlist_for_each_safe(pos, p, head) \
	for (pos = (head)->next; \
		(pos != NULL) && (p = pos->next, 1); \
		pos = p)

/*
 * cds_hlist_for_each_entry and cds_hlist_for_each_entry_safe take
 * respectively 4 and 5 arguments, while the Linux kernel APIs take 3,
 * and 4. We implement cds_hlist_for_each_entry_2() and
 * cds_hlist_for_each_entry_safe_2() to follow the Linux kernel APIs.
 */
#define cds_hlist_for_each_entry(entry, pos, head, member) \
	for (pos = (head)->next, \
			entry = cds_hlist_entry(pos, __typeof__(*entry), member); \
		pos != NULL; \
		pos = pos->next, \
			entry = cds_hlist_entry(pos, __typeof__(*entry), member))

#define cds_hlist_for_each_entry_safe(entry, pos, p, head, member) \
	for (pos = (head)->next, \
			entry = cds_hlist_entry(pos, __typeof__(*entry), member); \
		(pos != NULL) && (p = pos->next, 1); \
		pos = p, \
			entry = cds_hlist_entry(pos, __typeof__(*entry), member))

#define cds_hlist_for_each_entry_2(entry, head, member) \
	for (entry = cds_hlist_entry((head)->next, __typeof__(*entry), member); \
		&entry->member != NULL; \
		entry = cds_hlist_entry(entry->member.next, __typeof__(*entry), member))

#define cds_hlist_for_each_entry_safe_2(entry, e, head, member) \
	for (entry = cds_hlist_entry((head)->next, __typeof__(*entry), member); \
		(&entry->member != NULL) && (e = cds_hlist_entry(entry->member.next, \
						__typeof__(*entry), member), 1); \
		entry = e)

#endif	/* _KCOMPAT_HLIST_H */
