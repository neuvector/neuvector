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
 * This example shows how to remove nodes from a RCU lock-free hash table.
 * This hash table requires using a RCU scheme.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <urcu.h>		/* RCU flavor */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */
#include "jhash.h"		/* Example hash function */

/*
 * Nodes populated into the hash table.
 */
struct mynode {
	int value;			/* Node content */
	struct cds_lfht_node node;	/* Chaining in hash table */
	struct rcu_head rcu_head;	/* For call_rcu() */
};

static
int match(struct cds_lfht_node *ht_node, const void *_key)
{
	struct mynode *node =
		caa_container_of(ht_node, struct mynode, node);
	const unsigned int *key = _key;

	return *key == node->value;
}

static
void free_node(struct rcu_head *head)
{
	struct mynode *node = caa_container_of(head, struct mynode, rcu_head);

	free(node);
}

int main(int argc, char **argv)
{
	int values[] = { -5, 42, 42, 36, 24, };	/* 42 is duplicated */
	int remove_values[] = { 42, 36, 24, 123, };
	struct cds_lfht *ht;	/* Hash table */
	unsigned int i;
	int ret = 0;
	uint32_t seed;
	struct cds_lfht_iter iter;	/* For iteration on hash table */
	struct cds_lfht_node *ht_node;
	struct mynode *node;

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	/* Use time as seed for hash table hashing. */
	seed = (uint32_t) time(NULL);

	/*
	 * Allocate hash table.
	 */
	ht = cds_lfht_new(1, 1, 0,
		CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
		NULL);
	if (!ht) {
		printf("Error allocating hash table\n");
		ret = -1;
		goto end;
	}

	/*
	 * Add nodes to hash table.
	 */
	for (i = 0; i < CAA_ARRAY_SIZE(values); i++) {
		unsigned long hash;
		int value;

		node = malloc(sizeof(*node));
		if (!node) {
			ret = -1;
			goto end;
		}

		cds_lfht_node_init(&node->node);
		value = values[i];
		node->value = value;
		hash = jhash(&value, sizeof(value), seed);

		/*
		 * cds_lfht_add() needs to be called from RCU read-side
		 * critical section.
		 */
		rcu_read_lock();
		cds_lfht_add(ht, hash, &node->node);
		rcu_read_unlock();
	}

	/*
	 * Iterate over each hash table node. Those will appear in
	 * random order, depending on the hash seed. Iteration needs to
	 * be performed within RCU read-side critical section.
	 */
	printf("hash table content (random order):");
	rcu_read_lock();
	cds_lfht_for_each_entry(ht, &iter, node, node) {
		printf(" %d", node->value);
	}
	rcu_read_unlock();
	printf("\n");

	/*
	 * Remove one node for each key, if such a node is present.
	 */
	printf("removing keys (single key, not duplicates):");
	for (i = 0; i < CAA_ARRAY_SIZE(remove_values); i++) {
		unsigned long hash;
		int value;

		value = remove_values[i];
		hash = jhash(&value, sizeof(value), seed);
		printf(" %d", value);
		rcu_read_lock();
		cds_lfht_lookup(ht, hash, match, &value, &iter);
		ht_node = cds_lfht_iter_get_node(&iter);
		if (ht_node) {
			ret = cds_lfht_del(ht, ht_node);
			if (ret) {
				printf(" (concurrently deleted)");
			} else {
				struct mynode *del_node =
					caa_container_of(ht_node,
						struct mynode, node);
				call_rcu(&del_node->rcu_head, free_node);
			}
		} else {
			printf(" (not found)");
		}
		rcu_read_unlock();
	}
	printf("\n");

	printf("hash table content (random order):");
	rcu_read_lock();
	cds_lfht_for_each_entry(ht, &iter, node, node) {
		printf(" %d", node->value);
	}
	rcu_read_unlock();
	printf("\n");

end:
	rcu_unregister_thread();
	return ret;
}
