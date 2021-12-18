#ifndef _URCU_WFQUEUE_STATIC_H
#define _URCU_WFQUEUE_STATIC_H

/*
 * wfqueue-static.h
 *
 * Userspace RCU library - Queue with Wait-Free Enqueue/Blocking Dequeue
 *
 * TO BE INCLUDED ONLY IN LGPL-COMPATIBLE CODE. See wfqueue.h for linking
 * dynamically with the userspace rcu library.
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

#include <pthread.h>
#include <assert.h>
#include <poll.h>
#include <urcu/compiler.h>
#include <urcu/uatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Queue with wait-free enqueue/blocking dequeue.
 * This implementation adds a dummy head node when the queue is empty to ensure
 * we can always update the queue locklessly.
 *
 * Inspired from half-wait-free/half-blocking queue implementation done by
 * Paul E. McKenney.
 */

#define WFQ_ADAPT_ATTEMPTS		10	/* Retry if being set */
#define WFQ_WAIT			10	/* Wait 10 ms if being set */

static inline void _cds_wfq_node_init(struct cds_wfq_node *node)
{
	node->next = NULL;
}

static inline void _cds_wfq_init(struct cds_wfq_queue *q)
{
	int ret;

	_cds_wfq_node_init(&q->dummy);
	/* Set queue head and tail */
	q->head = &q->dummy;
	q->tail = &q->dummy.next;
	ret = pthread_mutex_init(&q->lock, NULL);
	assert(!ret);
}

static inline void _cds_wfq_enqueue(struct cds_wfq_queue *q,
				    struct cds_wfq_node *node)
{
	struct cds_wfq_node **old_tail;

	/*
	 * uatomic_xchg() implicit memory barrier orders earlier stores to data
	 * structure containing node and setting node->next to NULL before
	 * publication.
	 */
	old_tail = uatomic_xchg(&q->tail, &node->next);
	/*
	 * At this point, dequeuers see a NULL old_tail->next, which indicates
	 * that the queue is being appended to. The following store will append
	 * "node" to the queue from a dequeuer perspective.
	 */
	CMM_STORE_SHARED(*old_tail, node);
}

/*
 * Waiting for enqueuer to complete enqueue and return the next node
 */
static inline struct cds_wfq_node *
___cds_wfq_node_sync_next(struct cds_wfq_node *node)
{
	struct cds_wfq_node *next;
	int attempt = 0;

	/*
	 * Adaptative busy-looping waiting for enqueuer to complete enqueue.
	 */
	while ((next = CMM_LOAD_SHARED(node->next)) == NULL) {
		if (++attempt >= WFQ_ADAPT_ATTEMPTS) {
			poll(NULL, 0, WFQ_WAIT);	/* Wait for 10ms */
			attempt = 0;
		} else
			caa_cpu_relax();
	}

	return next;
}

/*
 * It is valid to reuse and free a dequeued node immediately.
 *
 * No need to go on a waitqueue here, as there is no possible state in which the
 * list could cause dequeue to busy-loop needlessly while waiting for another
 * thread to be scheduled. The queue appears empty until tail->next is set by
 * enqueue.
 */
static inline struct cds_wfq_node *
___cds_wfq_dequeue_blocking(struct cds_wfq_queue *q)
{
	struct cds_wfq_node *node, *next;

	/*
	 * Queue is empty if it only contains the dummy node.
	 */
	if (q->head == &q->dummy && CMM_LOAD_SHARED(q->tail) == &q->dummy.next)
		return NULL;
	node = q->head;

	next = ___cds_wfq_node_sync_next(node);

	/*
	 * Move queue head forward.
	 */
	q->head = next;
	/*
	 * Requeue dummy node if we just dequeued it.
	 */
	if (node == &q->dummy) {
		_cds_wfq_node_init(node);
		_cds_wfq_enqueue(q, node);
		return ___cds_wfq_dequeue_blocking(q);
	}
	return node;
}

static inline struct cds_wfq_node *
_cds_wfq_dequeue_blocking(struct cds_wfq_queue *q)
{
	struct cds_wfq_node *retnode;
	int ret;

	ret = pthread_mutex_lock(&q->lock);
	assert(!ret);
	retnode = ___cds_wfq_dequeue_blocking(q);
	ret = pthread_mutex_unlock(&q->lock);
	assert(!ret);
	return retnode;
}

#ifdef __cplusplus
}
#endif

#endif /* _URCU_WFQUEUE_STATIC_H */
