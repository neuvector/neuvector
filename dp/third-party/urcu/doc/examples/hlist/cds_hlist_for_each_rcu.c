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
 * This example shows how to do a non-circular RCU linked list
 * traversal, safely against concurrent RCU updates.
 * cds_hlist_for_each_rcu() iterates on struct cds_hlist_node, and thus,
 * either caa_container_of() or cds_hlist_entry() are needed to access
 * the container structure.
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
};

int main(int argc, char **argv)
{
	int values[] = { -5, 42, 36, 24, };
	CDS_HLIST_HEAD(mylist);		/* Defines an empty hlist head */
	unsigned int i;
	int ret = 0;
	struct cds_hlist_node *pos;

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	/*
	 * Adding nodes to the linked-list. Safe against concurrent
	 * RCU traversals, require mutual exclusion with list updates.
	 */
	for (i = 0; i < CAA_ARRAY_SIZE(values); i++) {
		struct mynode *node;

		node = malloc(sizeof(*node));
		if (!node) {
			ret = -1;
			goto end;
		}
		node->value = values[i];
		cds_hlist_add_head_rcu(&node->node, &mylist);
	}

	/*
	 * RCU-safe iteration on the list.
	 */
	printf("mylist content:");

	/*
	 * Surround the RCU read-side critical section with rcu_read_lock()
	 * and rcu_read_unlock().
	 */
	rcu_read_lock();

	/*
	 * This traversal can be performed concurrently with RCU
	 * updates.
	 */
	cds_hlist_for_each_rcu(pos, &mylist) {
		struct mynode *node = cds_hlist_entry(pos, struct mynode, node);

		printf(" %d", node->value);
	}

	rcu_read_unlock();

	printf("\n");
end:
	rcu_unregister_thread();
	return ret;
}
