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
 * This example shows how to remove from a non-circular linked-list
 * safely against concurrent RCU traversals.
 */

#include <stdio.h>

#include <urcu.h>		/* Userspace RCU flavor */
#include <urcu/rcuhlist.h>	/* RCU hlist */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */

/*
 * Nodes populated into the list.
 */
struct mynode {
	int value;			/* Node content */
	struct cds_hlist_node node;	/* Linked-list chaining */
	struct rcu_head rcu_head;	/* For call_rcu() */
};

static
void free_node_rcu(struct rcu_head *head)
{
	struct mynode *node = caa_container_of(head, struct mynode, rcu_head);

	free(node);
}

int main(int argc, char **argv)
{
	int values[] = { -5, 42, 36, 24, };
	CDS_HLIST_HEAD(mylist);		/* Defines an empty hlist head */
	unsigned int i;
	int ret = 0;
	struct mynode *node, *n;

	/*
	 * Adding nodes to the linked-list. Safe against concurrent
	 * RCU traversals, require mutual exclusion with list updates.
	 */
	for (i = 0; i < CAA_ARRAY_SIZE(values); i++) {
		node = malloc(sizeof(*node));
		if (!node) {
			ret = -1;
			goto end;
		}
		node->value = values[i];
		cds_hlist_add_head_rcu(&node->node, &mylist);
	}

	/*
	 * Removing all positive values. Safe against concurrent RCU
	 * traversals, require mutual exclusion with list updates.
	 * Notice the "safe" iteration: it is safe against removal of
	 * nodes as we iterate on the list.
	 */
	cds_hlist_for_each_entry_safe_2(node, n, &mylist, node) {
		if (node->value > 0) {
			cds_hlist_del_rcu(&node->node);
			/*
			 * We can only reclaim memory after a grace
			 * period has passed after cds_hlist_del_rcu().
			 */
			call_rcu(&node->rcu_head, free_node_rcu);
		}
	}

	/*
	 * Just show the list content. This is _not_ an RCU-safe
	 * iteration on the list.
	 */
	printf("mylist content:");
	cds_hlist_for_each_entry_2(node, &mylist, node) {
		printf(" %d", node->value);
	}
	printf("\n");
end:
	return ret;
}
