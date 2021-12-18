/*
 * wfcqueue.c
 *
 * Userspace RCU library - Concurrent Queue with Wait-Free Enqueue/Blocking Dequeue
 *
 * Copyright 2010-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011-2012 - Lai Jiangshan <laijs@cn.fujitsu.com>
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
#include "urcu/wfcqueue.h"
#include "urcu/static/wfcqueue.h"

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void cds_wfcq_node_init(struct cds_wfcq_node *node)
{
	_cds_wfcq_node_init(node);
}

void cds_wfcq_init(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	_cds_wfcq_init(head, tail);
}

bool cds_wfcq_empty(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)

{
	return _cds_wfcq_empty(head, tail);
}

bool cds_wfcq_enqueue(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		struct cds_wfcq_node *node)
{
	return _cds_wfcq_enqueue(head, tail, node);
}

void cds_wfcq_dequeue_lock(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	_cds_wfcq_dequeue_lock(head, tail);
}

void cds_wfcq_dequeue_unlock(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	_cds_wfcq_dequeue_unlock(head, tail);
}

struct cds_wfcq_node *cds_wfcq_dequeue_blocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	return _cds_wfcq_dequeue_blocking(head, tail);
}

struct cds_wfcq_node *cds_wfcq_dequeue_with_state_blocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		int *state)
{
	return _cds_wfcq_dequeue_with_state_blocking(head, tail, state);
}

enum cds_wfcq_ret cds_wfcq_splice_blocking(
		struct cds_wfcq_head *dest_q_head,
		struct cds_wfcq_tail *dest_q_tail,
		struct cds_wfcq_head *src_q_head,
		struct cds_wfcq_tail *src_q_tail)
{
	return _cds_wfcq_splice_blocking(dest_q_head, dest_q_tail,
				src_q_head, src_q_tail);
}

struct cds_wfcq_node *__cds_wfcq_dequeue_blocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	return ___cds_wfcq_dequeue_blocking(head, tail);
}

struct cds_wfcq_node *__cds_wfcq_dequeue_with_state_blocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		int *state)
{
	return ___cds_wfcq_dequeue_with_state_blocking(head, tail, state);
}

struct cds_wfcq_node *__cds_wfcq_dequeue_nonblocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	return ___cds_wfcq_dequeue_nonblocking(head, tail);
}

struct cds_wfcq_node *__cds_wfcq_dequeue_with_state_nonblocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		int *state)
{
	return ___cds_wfcq_dequeue_with_state_nonblocking(head, tail, state);
}

enum cds_wfcq_ret __cds_wfcq_splice_blocking(
		struct cds_wfcq_head *dest_q_head,
		struct cds_wfcq_tail *dest_q_tail,
		struct cds_wfcq_head *src_q_head,
		struct cds_wfcq_tail *src_q_tail)
{
	return ___cds_wfcq_splice_blocking(dest_q_head, dest_q_tail,
				src_q_head, src_q_tail);
}

enum cds_wfcq_ret __cds_wfcq_splice_nonblocking(
		struct cds_wfcq_head *dest_q_head,
		struct cds_wfcq_tail *dest_q_tail,
		struct cds_wfcq_head *src_q_head,
		struct cds_wfcq_tail *src_q_tail)
{
	return ___cds_wfcq_splice_nonblocking(dest_q_head, dest_q_tail,
				src_q_head, src_q_tail);
}

struct cds_wfcq_node *__cds_wfcq_first_blocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	return ___cds_wfcq_first_blocking(head, tail);
}

struct cds_wfcq_node *__cds_wfcq_first_nonblocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail)
{
	return ___cds_wfcq_first_nonblocking(head, tail);
}

struct cds_wfcq_node *__cds_wfcq_next_blocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		struct cds_wfcq_node *node)
{
	return ___cds_wfcq_next_blocking(head, tail, node);
}

struct cds_wfcq_node *__cds_wfcq_next_nonblocking(
		struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		struct cds_wfcq_node *node)
{
	return ___cds_wfcq_next_nonblocking(head, tail, node);
}
