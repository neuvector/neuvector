/*
 * wfqueue.c
 *
 * Userspace RCU library - Queue with Wait-Free Enqueue/Blocking Dequeue
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

/* Remove deprecation warnings from LGPL wrapper build. */
#define CDS_WFQ_DEPRECATED

/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#include "urcu/wfqueue.h"
#include "urcu/static/wfqueue.h"

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void cds_wfq_node_init(struct cds_wfq_node *node)
{
	_cds_wfq_node_init(node);
}

void cds_wfq_init(struct cds_wfq_queue *q)
{
	_cds_wfq_init(q);
}

void cds_wfq_enqueue(struct cds_wfq_queue *q, struct cds_wfq_node *node)
{
	_cds_wfq_enqueue(q, node);
}

struct cds_wfq_node *__cds_wfq_dequeue_blocking(struct cds_wfq_queue *q)
{
	return ___cds_wfq_dequeue_blocking(q);
}

struct cds_wfq_node *cds_wfq_dequeue_blocking(struct cds_wfq_queue *q)
{
	return _cds_wfq_dequeue_blocking(q);
}
