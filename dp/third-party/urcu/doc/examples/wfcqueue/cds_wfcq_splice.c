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
 * This example shows how to splice nodes from a source wfcqueue A into
 * a destination wfcqueue B.
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

static
int enqueue_values(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		int *values,
		size_t nr_values)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; i < nr_values; i++) {
		struct mynode *node;

		node = malloc(sizeof(*node));
		if (!node) {
			ret = -1;
			goto end;
		}
		cds_wfcq_node_init(&node->node);
		node->value = values[i];
		cds_wfcq_enqueue(head, tail, &node->node);
	}
end:
	return ret;
}

static
void print_queue(struct cds_wfcq_head *head,
		struct cds_wfcq_tail *tail,
		const char *qname)
{
	struct cds_wfcq_node *qnode;

	printf("%s:", qname);
	__cds_wfcq_for_each_blocking(head, tail, qnode) {
		struct mynode *node =
			caa_container_of(qnode, struct mynode, node);
		printf(" %d", node->value);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	int values_A[] = { -5, 42, 36, 24, };
	int values_B[] = { 200, 300, 400, };
	struct cds_wfcq_head head_A;	/* Queue A head */
	struct cds_wfcq_tail tail_A;	/* Queue A tail */
	struct cds_wfcq_head head_B;	/* Queue B head */
	struct cds_wfcq_tail tail_B;	/* Queue B tail */
	int ret = 0;

	cds_wfcq_init(&head_A, &tail_A);
	/* Enqueue nodes into A. */
	ret = enqueue_values(&head_A, &tail_A, values_A,
			CAA_ARRAY_SIZE(values_A));
	if (ret)
		goto end;
	cds_wfcq_init(&head_B, &tail_B);
	/* Enqueue nodes into B. */
	ret = enqueue_values(&head_B, &tail_B, values_B,
			CAA_ARRAY_SIZE(values_B));
	if (ret)
		goto end;

	print_queue(&head_A, &tail_A, "queue A content before splice");
	print_queue(&head_B, &tail_B, "queue B content before splice");

	/*
	 * Splice nodes from A into B.
	 */
	printf("Splicing queue A into queue B\n");
	(void) cds_wfcq_splice_blocking(&head_B, &tail_B,
			&head_A, &tail_A);

	print_queue(&head_A, &tail_A, "queue A content after splice");
	print_queue(&head_B, &tail_B, "queue B content after splice");
end:
	return ret;
}
