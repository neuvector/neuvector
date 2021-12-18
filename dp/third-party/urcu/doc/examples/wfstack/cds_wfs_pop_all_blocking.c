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
 * This example shows how to pop all nodes from a wfstack.
 */

#include <stdio.h>
#include <stdlib.h>

#include <urcu/wfstack.h>	/* Wait-free stack */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */

/*
 * Nodes populated into the stack.
 */
struct mynode {
	int value;			/* Node content */
	struct cds_wfs_node node;	/* Chaining in stack */
};

int main(int argc, char **argv)
{
	int values[] = { -5, 42, 36, 24, };
	struct cds_wfs_stack mystack;	/* Stack */
	unsigned int i;
	int ret = 0;
	struct cds_wfs_node *snode, *sn;
	struct cds_wfs_head *shead;

	cds_wfs_init(&mystack);

	/*
	 * Push nodes.
	 */
	for (i = 0; i < CAA_ARRAY_SIZE(values); i++) {
		struct mynode *node;

		node = malloc(sizeof(*node));
		if (!node) {
			ret = -1;
			goto end;
		}

		cds_wfs_node_init(&node->node);
		node->value = values[i];
		cds_wfs_push(&mystack, &node->node);
	}

	/*
	 * Pop all nodes from mystack into shead. The head can the be
	 * used for iteration.
	 */
	shead = cds_wfs_pop_all_blocking(&mystack);

	/*
	 * Show the stack content, iterate in reverse order of push,
	 * from newest to oldest. Use cds_wfs_for_each_blocking_safe()
	 * so we can free the nodes as we iterate.
	 */
	printf("mystack content:");
	cds_wfs_for_each_blocking_safe(shead, snode, sn) {
		struct mynode *node =
			caa_container_of(snode, struct mynode, node);
		printf(" %d", node->value);
		free(node);
	}
	printf("\n");
end:
	return ret;
}
