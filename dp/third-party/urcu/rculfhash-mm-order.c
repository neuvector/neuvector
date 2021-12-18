/*
 * rculfhash-mm-order.c
 *
 * Order based memory management for Lock-Free RCU Hash Table
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

#include <rculfhash-internal.h>

static
void cds_lfht_alloc_bucket_table(struct cds_lfht *ht, unsigned long order)
{
	if (order == 0) {
		ht->tbl_order[0] = calloc(ht->min_nr_alloc_buckets,
			sizeof(struct cds_lfht_node));
		assert(ht->tbl_order[0]);
	} else if (order > ht->min_alloc_buckets_order) {
		ht->tbl_order[order] = calloc(1UL << (order -1),
			sizeof(struct cds_lfht_node));
		assert(ht->tbl_order[order]);
	}
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

/*
 * cds_lfht_free_bucket_table() should be called with decreasing order.
 * When cds_lfht_free_bucket_table(0) is called, it means the whole
 * lfht is destroyed.
 */
static
void cds_lfht_free_bucket_table(struct cds_lfht *ht, unsigned long order)
{
	if (order == 0)
		poison_free(ht->tbl_order[0]);
	else if (order > ht->min_alloc_buckets_order)
		poison_free(ht->tbl_order[order]);
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

static
struct cds_lfht_node *bucket_at(struct cds_lfht *ht, unsigned long index)
{
	unsigned long order;

	if (index < ht->min_nr_alloc_buckets) {
		dbg_printf("bucket index %lu order 0 aridx 0\n", index);
		return &ht->tbl_order[0][index];
	}
	/*
	 * equivalent to cds_lfht_get_count_order_ulong(index + 1), but
	 * optimizes away the non-existing 0 special-case for
	 * cds_lfht_get_count_order_ulong.
	 */
	order = cds_lfht_fls_ulong(index);
	dbg_printf("bucket index %lu order %lu aridx %lu\n",
		   index, order, index & ((1UL << (order - 1)) - 1));
	return &ht->tbl_order[order][index & ((1UL << (order - 1)) - 1)];
}

static
struct cds_lfht *alloc_cds_lfht(unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	return __default_alloc_cds_lfht(
			&cds_lfht_mm_order, sizeof(struct cds_lfht),
			min_nr_alloc_buckets, max_nr_buckets);
}

const struct cds_lfht_mm_type cds_lfht_mm_order = {
	.alloc_cds_lfht = alloc_cds_lfht,
	.alloc_bucket_table = cds_lfht_alloc_bucket_table,
	.free_bucket_table = cds_lfht_free_bucket_table,
	.bucket_at = bucket_at,
};
