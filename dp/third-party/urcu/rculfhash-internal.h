#ifndef _URCU_RCULFHASH_INTERNAL_H
#define _URCU_RCULFHASH_INTERNAL_H

/*
 * urcu/rculfhash-internal.h
 *
 * Internal header for Lock-Free RCU Hash Table
 *
 * Copyright 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 - Lai Jiangshan <laijs@cn.fujitsu.com>
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

#include <urcu/rculfhash.h>
#include <stdio.h>

#ifdef DEBUG
#define dbg_printf(fmt, args...)     printf("[debug rculfhash] " fmt, ## args)
#else
#define dbg_printf(fmt, args...)				\
do {								\
	/* do nothing but check printf format */		\
	if (0)							\
		printf("[debug rculfhash] " fmt, ## args);	\
} while (0)
#endif

#if (CAA_BITS_PER_LONG == 32)
#define MAX_TABLE_ORDER			32
#else
#define MAX_TABLE_ORDER			64
#endif

#define MAX_CHUNK_TABLE			(1UL << 10)

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

struct ht_items_count;

/*
 * cds_lfht: Top-level data structure representing a lock-free hash
 * table. Defined in the implementation file to make it be an opaque
 * cookie to users.
 *
 * The fields used in fast-paths are placed near the end of the
 * structure, because we need to have a variable-sized union to contain
 * the mm plugin fields, which are used in the fast path.
 */
struct cds_lfht {
	/* Initial configuration items */
	unsigned long max_nr_buckets;
	const struct cds_lfht_mm_type *mm;	/* memory management plugin */
	const struct rcu_flavor_struct *flavor;	/* RCU flavor */

	long count;			/* global approximate item count */

	/*
	 * We need to put the work threads offline (QSBR) when taking this
	 * mutex, because we use synchronize_rcu within this mutex critical
	 * section, which waits on read-side critical sections, and could
	 * therefore cause grace-period deadlock if we hold off RCU G.P.
	 * completion.
	 */
	pthread_mutex_t resize_mutex;	/* resize mutex: add/del mutex */
	pthread_attr_t *resize_attr;	/* Resize threads attributes */
	unsigned int in_progress_resize, in_progress_destroy;
	unsigned long resize_target;
	int resize_initiated;

	/*
	 * Variables needed for add and remove fast-paths.
	 */
	int flags;
	unsigned long min_alloc_buckets_order;
	unsigned long min_nr_alloc_buckets;
	struct ht_items_count *split_count;	/* split item count */

	/*
	 * Variables needed for the lookup, add and remove fast-paths.
	 */
	unsigned long size;	/* always a power of 2, shared (RCU) */
	/*
	 * bucket_at pointer is kept here to skip the extra level of
	 * dereference needed to get to "mm" (this is a fast-path).
	 */
	struct cds_lfht_node *(*bucket_at)(struct cds_lfht *ht,
			unsigned long index);
	/*
	 * Dynamic length "tbl_chunk" needs to be at the end of
	 * cds_lfht.
	 */
	union {
		/*
		 * Contains the per order-index-level bucket node table.
		 * The size of each bucket node table is half the number
		 * of hashes contained in this order (except for order 0).
		 * The minimum allocation buckets size parameter allows
		 * combining the bucket node arrays of the lowermost
		 * levels to improve cache locality for small index orders.
		 */
		struct cds_lfht_node *tbl_order[MAX_TABLE_ORDER];

		/*
		 * Contains the bucket node chunks. The size of each
		 * bucket node chunk is ->min_alloc_size (we avoid to
		 * allocate chunks with different size). Chunks improve
		 * cache locality for small index orders, and are more
		 * friendly with environments where allocation of large
		 * contiguous memory areas is challenging due to memory
		 * fragmentation concerns or inability to use virtual
		 * memory addressing.
		 */
		struct cds_lfht_node *tbl_chunk[0];

		/*
		 * Memory mapping with room for all possible buckets.
		 * Their memory is allocated when needed.
		 */
		struct cds_lfht_node *tbl_mmap;
	};
	/*
	 * End of variables needed for the lookup, add and remove
	 * fast-paths.
	 */
};

extern unsigned int cds_lfht_fls_ulong(unsigned long x);
extern int cds_lfht_get_count_order_ulong(unsigned long x);

#ifdef POISON_FREE
#define poison_free(ptr)					\
	do {							\
		if (ptr) {					\
			memset(ptr, 0x42, sizeof(*(ptr)));	\
			free(ptr);				\
		}						\
	} while (0)
#else
#define poison_free(ptr)	free(ptr)
#endif

static inline
struct cds_lfht *__default_alloc_cds_lfht(
		const struct cds_lfht_mm_type *mm,
		unsigned long cds_lfht_size,
		unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	struct cds_lfht *ht;

	ht = calloc(1, cds_lfht_size);
	assert(ht);

	ht->mm = mm;
	ht->bucket_at = mm->bucket_at;
	ht->min_nr_alloc_buckets = min_nr_alloc_buckets;
	ht->min_alloc_buckets_order =
		cds_lfht_get_count_order_ulong(min_nr_alloc_buckets);
	ht->max_nr_buckets = max_nr_buckets;

	return ht;
}

#endif /* _URCU_RCULFHASH_INTERNAL_H */
