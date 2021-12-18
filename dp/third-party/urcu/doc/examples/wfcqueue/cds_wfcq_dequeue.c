/*
 * Copyright (C) 2013  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program for any
 * purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is
 * granted, provided the above notices are retained, and a notice that
 * the code was modified is included with the above copyright notice.
 *
 * This example shows how to dequeue nodes from a wfcqueue.
 */

#include <stdio.h>
#include <stdlib.h>

#include <urcu/wfcqueue.h>	/* Wait-free concurrent queue */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */

/*
 * Nodes populated into the queue.
 */
struct mynode {
	int value;			/* Node content */
	struct cds_wfcq_node node;	/* Chaining in queue */
};

int main(int argc, char **argv)
{
	int values[] = { -5, 42, 36, 24, };
	struct cds_wfcq_head myqueue_head;	/* Queue head */
	struct cds_wfcq_tail myqueue_tail;	/* Queue tail */
	unsigned int i;
	int ret = 0;

	cds_wfcq_init(&myqueue_head, &myqueue_tail);

	/*
	 * Enqueue nodes.
	 */
	for (i = 0; i < CAA_ARRAY_SIZE(values); i++) {
		struct mynode *node;

		node = malloc(sizeof(*node));
		if (!node) {
			ret = -1;
			goto end;
		}

		cds_wfcq_node_init(&node->node);
		node->value = values[i];
		cds_wfcq_enqueue(&myqueue_head, &myqueue_tail,
				&node->node);
	}

	/*
	 * Dequeue each node from the queue. Those will be dequeued from
	 * the oldest (first enqueued) to the newest (last enqueued).
	 */
	printf("dequeued content:");
	for (;;) {
		struct cds_wfcq_node *qnode;
		struct mynode *node;

		qnode = cds_wfcq_dequeue_blocking(&myqueue_head, &myqueue_tail);
		if (!qnode) {
			break;	/* Queue is empty. */
		}
		/* Getting the container structure from the node */
		node = caa_container_of(qnode, struct mynode, node);
		printf(" %d", node->value);
		free(node);
	}
	printf("\n");
end:
	return ret;
}
