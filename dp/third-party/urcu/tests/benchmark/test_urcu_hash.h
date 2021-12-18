#ifndef _TEST_URCU_HASH_H
#define _TEST_URCU_HASH_H

/*
 * test_urcu_hash.h
 *
 * Userspace RCU library - test program
 *
 * Copyright 2009-2012 - Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <urcu/tls-compat.h>
#include "cpuset.h"
#include "thread-id.h"
#include "../common/debug-yield.h"

#define DEFAULT_HASH_SIZE	32
#define DEFAULT_MIN_ALLOC_SIZE	1
#define DEFAULT_RAND_POOL	1000000

/*
 * Note: the hash seed should be a random value for hash tables
 * targeting production environments to provide protection against
 * denial of service attacks. We keep it a static value within this test
 * program to compare identical benchmark runs.
 */
#define TEST_HASH_SEED	0x42UL

/* hardcoded number of CPUs */
#define NR_CPUS 16384

#ifdef POISON_FREE
#define poison_free(ptr)				\
	do {						\
		memset(ptr, 0x42, sizeof(*(ptr)));	\
		free(ptr);				\
	} while (0)
#else
#define poison_free(ptr)	free(ptr)
#endif

#ifndef DYNAMIC_LINK_TEST
#define _LGPL_SOURCE
#else
#define debug_yield_read()
#endif
#include <urcu-qsbr.h>
#include <urcu/rculfhash.h>
#include <urcu-call-rcu.h>

struct wr_count {
	unsigned long update_ops;
	unsigned long add;
	unsigned long add_exist;
	unsigned long remove;
};

extern DECLARE_URCU_TLS(unsigned int, rand_lookup);
extern DECLARE_URCU_TLS(unsigned long, nr_add);
extern DECLARE_URCU_TLS(unsigned long, nr_addexist);
extern DECLARE_URCU_TLS(unsigned long, nr_del);
extern DECLARE_URCU_TLS(unsigned long, nr_delnoent);
extern DECLARE_URCU_TLS(unsigned long, lookup_fail);
extern DECLARE_URCU_TLS(unsigned long, lookup_ok);

extern struct cds_lfht *test_ht;

struct test_data {
	int a;
	int b;
};

struct lfht_test_node {
	struct cds_lfht_node node;
	void *key;
	unsigned int key_len;
	/* cache-cold for iteration */
	struct rcu_head head;
};

static inline struct lfht_test_node *
to_test_node(struct cds_lfht_node *node)
{
	return caa_container_of(node, struct lfht_test_node, node);
}

static inline
void lfht_test_node_init(struct lfht_test_node *node, void *key,
			size_t key_len)
{
	cds_lfht_node_init(&node->node);
	node->key = key;
	node->key_len = key_len;
}

static inline struct lfht_test_node *
cds_lfht_iter_get_test_node(struct cds_lfht_iter *iter)
{
	return to_test_node(cds_lfht_iter_get_node(iter));
}

extern volatile int test_go, test_stop;

extern unsigned long wdelay;

extern unsigned long duration;

/* read-side C.S. duration, in loops */
extern unsigned long rduration;

extern unsigned long init_hash_size;
extern unsigned long min_hash_alloc_size;
extern unsigned long max_hash_buckets_size;
extern unsigned long init_populate;
extern int opt_auto_resize;
extern int add_only, add_unique, add_replace;
extern const struct cds_lfht_mm_type *memory_backend;

extern unsigned long init_pool_offset, lookup_pool_offset, write_pool_offset;
extern unsigned long init_pool_size,
	lookup_pool_size,
	write_pool_size;
extern int validate_lookup;

extern unsigned long nr_hash_chains;

extern int count_pipe[2];

static inline void loop_sleep(unsigned long loops)
{
	while (loops-- != 0)
		caa_cpu_relax();
}

extern int verbose_mode;

#define printf_verbose(fmt, args...)		\
	do {					\
		if (verbose_mode)		\
			printf(fmt, ## args);	\
	} while (0)

extern unsigned int cpu_affinities[NR_CPUS];
extern unsigned int next_aff;
extern int use_affinity;

extern pthread_mutex_t affinity_mutex;

void set_affinity(void);

/*
 * returns 0 if test should end.
 */
static inline int test_duration_write(void)
{
	return !test_stop;
}

static inline int test_duration_read(void)
{
	return !test_stop;
}

extern DECLARE_URCU_TLS(unsigned long long, nr_writes);
extern DECLARE_URCU_TLS(unsigned long long, nr_reads);

extern unsigned int nr_readers;
extern unsigned int nr_writers;

void rcu_copy_mutex_lock(void);
void rcu_copy_mutex_unlock(void);

/*
 * Hash function
 * Source: http://burtleburtle.net/bob/c/lookup3.c
 * Originally Public Domain
 */

#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c) \
do { \
	a -= c; a ^= rot(c,  4); c += b; \
	b -= a; b ^= rot(a,  6); a += c; \
	c -= b; c ^= rot(b,  8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b,  4); b += a; \
} while (0)

#define final(a, b, c) \
{ \
	c ^= b; c -= rot(b, 14); \
	a ^= c; a -= rot(c, 11); \
	b ^= a; b -= rot(a, 25); \
	c ^= b; c -= rot(b, 16); \
	a ^= c; a -= rot(c,  4);\
	b ^= a; b -= rot(a, 14); \
	c ^= b; c -= rot(b, 24); \
}

static inline __attribute__((unused))
uint32_t hash_u32(
	const uint32_t *k,	/* the key, an array of uint32_t values */
	size_t length,		/* the length of the key, in uint32_ts */
	uint32_t initval)	/* the previous hash, or an arbitrary value */
{
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + (((uint32_t) length) << 2) + initval;

	/*----------------------------------------- handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/*----------------------------------- handle the last 3 uint32_t's */
	switch (length) {	/* all the case statements fall through */
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		final(a, b, c);
	case 0:			/* case 0: nothing left to add */
		break;
	}
	/*---------------------------------------------- report the result */
	return c;
}

static inline
void hashword2(
	const uint32_t *k,	/* the key, an array of uint32_t values */
	size_t length,		/* the length of the key, in uint32_ts */
	uint32_t *pc,		/* IN: seed OUT: primary hash value */
	uint32_t *pb)		/* IN: more seed OUT: secondary hash value */
{
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((uint32_t) (length << 2)) + *pc;
	c += *pb;

	/*----------------------------------------- handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/*----------------------------------- handle the last 3 uint32_t's */
	switch (length) {	/* all the case statements fall through */
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		final(a, b, c);
	case 0:			/* case 0: nothing left to add */
		break;
	}
	/*---------------------------------------------- report the result */
	*pc = c;
	*pb = b;
}

#if (CAA_BITS_PER_LONG == 32)
static inline
unsigned long test_hash_mix(const void *_key, size_t length, unsigned long seed)
{
	unsigned int key = (unsigned int) _key;

	assert(length == sizeof(unsigned int));
	return hash_u32(&key, 1, seed);
}
#else
static inline
unsigned long test_hash_mix(const void *_key, size_t length, unsigned long seed)
{
	union {
		uint64_t v64;
		uint32_t v32[2];
	} v;
	union {
		uint64_t v64;
		uint32_t v32[2];
	} key;

	assert(length == sizeof(unsigned long));
	v.v64 = (uint64_t) seed;
	key.v64 = (uint64_t) _key;
	hashword2(key.v32, 2, &v.v32[0], &v.v32[1]);
	return v.v64;
}
#endif

/*
 * Hash function with nr_hash_chains != 0 for testing purpose only!
 * Creates very long hash chains, deteriorating the hash table into a
 * few linked lists, depending on the nr_hash_chains value. The purpose
 * of this test is to check how the hash table behaves with hash chains
 * containing different values, which is a rare case in a normal hash
 * table.
 */
static inline
unsigned long test_hash(const void *_key, size_t length,
			unsigned long seed)
{
	if (nr_hash_chains == 0) {
		return test_hash_mix(_key, length, seed);
	} else {
		unsigned long v;

		assert(length == sizeof(unsigned long));
		v = (unsigned long) _key;
		return v % nr_hash_chains;
	}
}

unsigned long test_compare(const void *key1, size_t key1_len,
                           const void *key2, size_t key2_len);

static inline
int test_match(struct cds_lfht_node *node, const void *key)
{
	struct lfht_test_node *test_node = to_test_node(node);

	return !test_compare(test_node->key, test_node->key_len,
			key, sizeof(unsigned long));
}

static inline
void cds_lfht_test_lookup(struct cds_lfht *ht, void *key, size_t key_len,
		struct cds_lfht_iter *iter)
{
	assert(key_len == sizeof(unsigned long));

	cds_lfht_lookup(ht, test_hash(key, key_len, TEST_HASH_SEED),
			test_match, key, iter);
}

void free_node_cb(struct rcu_head *head);

/* rw test */
void test_hash_rw_sigusr1_handler(int signo);
void test_hash_rw_sigusr2_handler(int signo);
void *test_hash_rw_thr_reader(void *_count);
void *test_hash_rw_thr_writer(void *_count);
int test_hash_rw_populate_hash(void);

/* unique test */
void test_hash_unique_sigusr1_handler(int signo);
void test_hash_unique_sigusr2_handler(int signo);
void *test_hash_unique_thr_reader(void *_count);
void *test_hash_unique_thr_writer(void *_count);
int test_hash_unique_populate_hash(void);

#endif /* _TEST_URCU_HASH_H */
