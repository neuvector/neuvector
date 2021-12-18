/*
 * urcu-bp.c
 *
 * Userspace RCU library, "bulletproof" version.
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
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
 *
 * IBM's contributions to this file may be relicensed under LGPLv2 or later.
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/mman.h>

#include "urcu/wfcqueue.h"
#include "urcu/map/urcu-bp.h"
#include "urcu/static/urcu-bp.h"
#include "urcu-pointer.h"
#include "urcu/tls-compat.h"

#include "urcu-die.h"

/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#undef _LGPL_SOURCE
#include "urcu-bp.h"
#define _LGPL_SOURCE

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifdef __linux__
static
void *mremap_wrapper(void *old_address, size_t old_size,
		size_t new_size, int flags)
{
	return mremap(old_address, old_size, new_size, flags);
}
#else

#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

/*
 * mremap wrapper for non-Linux systems not allowing MAYMOVE.
 * This is not generic.
*/
static
void *mremap_wrapper(void *old_address, size_t old_size,
		size_t new_size, int flags)
{
	assert(!(flags & MREMAP_MAYMOVE));

	return MAP_FAILED;
}
#endif

/* Sleep delay in ms */
#define RCU_SLEEP_DELAY_MS	10
#define INIT_NR_THREADS		8
#define ARENA_INIT_ALLOC		\
	sizeof(struct registry_chunk)	\
	+ INIT_NR_THREADS * sizeof(struct rcu_reader)

/*
 * Active attempts to check for reader Q.S. before calling sleep().
 */
#define RCU_QS_ACTIVE_ATTEMPTS 100

static
int rcu_bp_refcount;

static
void __attribute__((constructor)) rcu_bp_init(void);
static
void __attribute__((destructor)) _rcu_bp_exit(void);

/*
 * rcu_gp_lock ensures mutual exclusion between threads calling
 * synchronize_rcu().
 */
static pthread_mutex_t rcu_gp_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * rcu_registry_lock ensures mutual exclusion between threads
 * registering and unregistering themselves to/from the registry, and
 * with threads reading that registry from synchronize_rcu(). However,
 * this lock is not held all the way through the completion of awaiting
 * for the grace period. It is sporadically released between iterations
 * on the registry.
 * rcu_registry_lock may nest inside rcu_gp_lock.
 */
static pthread_mutex_t rcu_registry_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static int initialized;

static pthread_key_t urcu_bp_key;

#ifdef DEBUG_YIELD
unsigned int rcu_yield_active;
__DEFINE_URCU_TLS_GLOBAL(unsigned int, rcu_rand_yield);
#endif

struct rcu_gp rcu_gp = { .ctr = RCU_GP_COUNT };

/*
 * Pointer to registry elements. Written to only by each individual reader. Read
 * by both the reader and the writers.
 */
__DEFINE_URCU_TLS_GLOBAL(struct rcu_reader *, rcu_reader);

static CDS_LIST_HEAD(registry);

struct registry_chunk {
	size_t data_len;		/* data length */
	size_t used;			/* amount of data used */
	struct cds_list_head node;	/* chunk_list node */
	char data[];
};

struct registry_arena {
	struct cds_list_head chunk_list;
};

static struct registry_arena registry_arena = {
	.chunk_list = CDS_LIST_HEAD_INIT(registry_arena.chunk_list),
};

/* Saved fork signal mask, protected by rcu_gp_lock */
static sigset_t saved_fork_signal_mask;

static void mutex_lock(pthread_mutex_t *mutex)
{
	int ret;

#ifndef DISTRUST_SIGNALS_EXTREME
	ret = pthread_mutex_lock(mutex);
	if (ret)
		urcu_die(ret);
#else /* #ifndef DISTRUST_SIGNALS_EXTREME */
	while ((ret = pthread_mutex_trylock(mutex)) != 0) {
		if (ret != EBUSY && ret != EINTR)
			urcu_die(ret);
		poll(NULL,0,10);
	}
#endif /* #else #ifndef DISTRUST_SIGNALS_EXTREME */
}

static void mutex_unlock(pthread_mutex_t *mutex)
{
	int ret;

	ret = pthread_mutex_unlock(mutex);
	if (ret)
		urcu_die(ret);
}

/*
 * Always called with rcu_registry lock held. Releases this lock between
 * iterations and grabs it again. Holds the lock when it returns.
 */
static void wait_for_readers(struct cds_list_head *input_readers,
			struct cds_list_head *cur_snap_readers,
			struct cds_list_head *qsreaders)
{
	unsigned int wait_loops = 0;
	struct rcu_reader *index, *tmp;

	/*
	 * Wait for each thread URCU_TLS(rcu_reader).ctr to either
	 * indicate quiescence (not nested), or observe the current
	 * rcu_gp.ctr value.
	 */
	for (;;) {
		if (wait_loops < RCU_QS_ACTIVE_ATTEMPTS)
			wait_loops++;

		cds_list_for_each_entry_safe(index, tmp, input_readers, node) {
			switch (rcu_reader_state(&index->ctr)) {
			case RCU_READER_ACTIVE_CURRENT:
				if (cur_snap_readers) {
					cds_list_move(&index->node,
						cur_snap_readers);
					break;
				}
				/* Fall-through */
			case RCU_READER_INACTIVE:
				cds_list_move(&index->node, qsreaders);
				break;
			case RCU_READER_ACTIVE_OLD:
				/*
				 * Old snapshot. Leaving node in
				 * input_readers will make us busy-loop
				 * until the snapshot becomes current or
				 * the reader becomes inactive.
				 */
				break;
			}
		}

		if (cds_list_empty(input_readers)) {
			break;
		} else {
			/* Temporarily unlock the registry lock. */
			mutex_unlock(&rcu_registry_lock);
			if (wait_loops >= RCU_QS_ACTIVE_ATTEMPTS)
				(void) poll(NULL, 0, RCU_SLEEP_DELAY_MS);
			else
				caa_cpu_relax();
			/* Re-lock the registry lock before the next loop. */
			mutex_lock(&rcu_registry_lock);
		}
	}
}

void synchronize_rcu(void)
{
	CDS_LIST_HEAD(cur_snap_readers);
	CDS_LIST_HEAD(qsreaders);
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	assert(!ret);
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	assert(!ret);

	mutex_lock(&rcu_gp_lock);

	mutex_lock(&rcu_registry_lock);

	if (cds_list_empty(&registry))
		goto out;

	/* All threads should read qparity before accessing data structure
	 * where new ptr points to. */
	/* Write new ptr before changing the qparity */
	cmm_smp_mb();

	/*
	 * Wait for readers to observe original parity or be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	wait_for_readers(&registry, &cur_snap_readers, &qsreaders);

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/* Switch parity: 0 -> 1, 1 -> 0 */
	CMM_STORE_SHARED(rcu_gp.ctr, rcu_gp.ctr ^ RCU_GP_CTR_PHASE);

	/*
	 * Must commit qparity update to memory before waiting for other parity
	 * quiescent state. Failure to do so could result in the writer waiting
	 * forever while new readers are always accessing data (no progress).
	 * Ensured by CMM_STORE_SHARED and CMM_LOAD_SHARED.
	 */

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/*
	 * Wait for readers to observe new parity or be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	wait_for_readers(&cur_snap_readers, NULL, &qsreaders);

	/*
	 * Put quiescent reader list back into registry.
	 */
	cds_list_splice(&qsreaders, &registry);

	/*
	 * Finish waiting for reader threads before letting the old ptr being
	 * freed.
	 */
	cmm_smp_mb();
out:
	mutex_unlock(&rcu_registry_lock);
	mutex_unlock(&rcu_gp_lock);
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	assert(!ret);
}

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void rcu_read_lock(void)
{
	_rcu_read_lock();
}

void rcu_read_unlock(void)
{
	_rcu_read_unlock();
}

int rcu_read_ongoing(void)
{
	return _rcu_read_ongoing();
}

/*
 * Only grow for now. If empty, allocate a ARENA_INIT_ALLOC sized chunk.
 * Else, try expanding the last chunk. If this fails, allocate a new
 * chunk twice as big as the last chunk.
 * Memory used by chunks _never_ moves. A chunk could theoretically be
 * freed when all "used" slots are released, but we don't do it at this
 * point.
 */
static
void expand_arena(struct registry_arena *arena)
{
	struct registry_chunk *new_chunk, *last_chunk;
	size_t old_chunk_len, new_chunk_len;

	/* No chunk. */
	if (cds_list_empty(&arena->chunk_list)) {
		assert(ARENA_INIT_ALLOC >=
			sizeof(struct registry_chunk)
			+ sizeof(struct rcu_reader));
		new_chunk_len = ARENA_INIT_ALLOC;
		new_chunk = mmap(NULL, new_chunk_len,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1, 0);
		if (new_chunk == MAP_FAILED)
			abort();
		bzero(new_chunk, new_chunk_len);
		new_chunk->data_len =
			new_chunk_len - sizeof(struct registry_chunk);
		cds_list_add_tail(&new_chunk->node, &arena->chunk_list);
		return;		/* We're done. */
	}

	/* Try expanding last chunk. */
	last_chunk = cds_list_entry(arena->chunk_list.prev,
		struct registry_chunk, node);
	old_chunk_len =
		last_chunk->data_len + sizeof(struct registry_chunk);
	new_chunk_len = old_chunk_len << 1;

	/* Don't allow memory mapping to move, just expand. */
	new_chunk = mremap_wrapper(last_chunk, old_chunk_len,
		new_chunk_len, 0);
	if (new_chunk != MAP_FAILED) {
		/* Should not have moved. */
		assert(new_chunk == last_chunk);
		bzero((char *) last_chunk + old_chunk_len,
			new_chunk_len - old_chunk_len);
		last_chunk->data_len =
			new_chunk_len - sizeof(struct registry_chunk);
		return;		/* We're done. */
	}

	/* Remap did not succeed, we need to add a new chunk. */
	new_chunk = mmap(NULL, new_chunk_len,
		PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1, 0);
	if (new_chunk == MAP_FAILED)
		abort();
	bzero(new_chunk, new_chunk_len);
	new_chunk->data_len =
		new_chunk_len - sizeof(struct registry_chunk);
	cds_list_add_tail(&new_chunk->node, &arena->chunk_list);
}

static
struct rcu_reader *arena_alloc(struct registry_arena *arena)
{
	struct registry_chunk *chunk;
	struct rcu_reader *rcu_reader_reg;
	int expand_done = 0;	/* Only allow to expand once per alloc */
	size_t len = sizeof(struct rcu_reader);

retry:
	cds_list_for_each_entry(chunk, &arena->chunk_list, node) {
		if (chunk->data_len - chunk->used < len)
			continue;
		/* Find spot */
		for (rcu_reader_reg = (struct rcu_reader *) &chunk->data[0];
				rcu_reader_reg < (struct rcu_reader *) &chunk->data[chunk->data_len];
				rcu_reader_reg++) {
			if (!rcu_reader_reg->alloc) {
				rcu_reader_reg->alloc = 1;
				chunk->used += len;
				return rcu_reader_reg;
			}
		}
	}

	if (!expand_done) {
		expand_arena(arena);
		expand_done = 1;
		goto retry;
	}

	return NULL;
}

/* Called with signals off and mutex locked */
static
void add_thread(void)
{
	struct rcu_reader *rcu_reader_reg;
	int ret;

	rcu_reader_reg = arena_alloc(&registry_arena);
	if (!rcu_reader_reg)
		abort();
	ret = pthread_setspecific(urcu_bp_key, rcu_reader_reg);
	if (ret)
		abort();

	/* Add to registry */
	rcu_reader_reg->tid = pthread_self();
	assert(rcu_reader_reg->ctr == 0);
	cds_list_add(&rcu_reader_reg->node, &registry);
	/*
	 * Reader threads are pointing to the reader registry. This is
	 * why its memory should never be relocated.
	 */
	URCU_TLS(rcu_reader) = rcu_reader_reg;
}

/* Called with mutex locked */
static
void cleanup_thread(struct registry_chunk *chunk,
		struct rcu_reader *rcu_reader_reg)
{
	rcu_reader_reg->ctr = 0;
	cds_list_del(&rcu_reader_reg->node);
	rcu_reader_reg->tid = 0;
	rcu_reader_reg->alloc = 0;
	chunk->used -= sizeof(struct rcu_reader);
}

static
struct registry_chunk *find_chunk(struct rcu_reader *rcu_reader_reg)
{
	struct registry_chunk *chunk;

	cds_list_for_each_entry(chunk, &registry_arena.chunk_list, node) {
		if (rcu_reader_reg < (struct rcu_reader *) &chunk->data[0])
			continue;
		if (rcu_reader_reg >= (struct rcu_reader *) &chunk->data[chunk->data_len])
			continue;
		return chunk;
	}
	return NULL;
}

/* Called with signals off and mutex locked */
static
void remove_thread(struct rcu_reader *rcu_reader_reg)
{
	cleanup_thread(find_chunk(rcu_reader_reg), rcu_reader_reg);
	URCU_TLS(rcu_reader) = NULL;
}

/* Disable signals, take mutex, add to registry */
void rcu_bp_register(void)
{
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	if (ret)
		abort();
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	if (ret)
		abort();

	/*
	 * Check if a signal concurrently registered our thread since
	 * the check in rcu_read_lock().
	 */
	if (URCU_TLS(rcu_reader))
		goto end;

	/*
	 * Take care of early registration before urcu_bp constructor.
	 */
	rcu_bp_init();

	mutex_lock(&rcu_registry_lock);
	add_thread();
	mutex_unlock(&rcu_registry_lock);
end:
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	if (ret)
		abort();
}

/* Disable signals, take mutex, remove from registry */
static
void rcu_bp_unregister(struct rcu_reader *rcu_reader_reg)
{
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	if (ret)
		abort();
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	if (ret)
		abort();

	mutex_lock(&rcu_registry_lock);
	remove_thread(rcu_reader_reg);
	mutex_unlock(&rcu_registry_lock);
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	if (ret)
		abort();
	_rcu_bp_exit();
}

/*
 * Remove thread from the registry when it exits, and flag it as
 * destroyed so garbage collection can take care of it.
 */
static
void urcu_bp_thread_exit_notifier(void *rcu_key)
{
	rcu_bp_unregister(rcu_key);
}

static
void rcu_bp_init(void)
{
	mutex_lock(&init_lock);
	if (!rcu_bp_refcount++) {
		int ret;

		ret = pthread_key_create(&urcu_bp_key,
				urcu_bp_thread_exit_notifier);
		if (ret)
			abort();
		initialized = 1;
	}
	mutex_unlock(&init_lock);
}

static
void _rcu_bp_exit(void)
{
	mutex_lock(&init_lock);
	if (!--rcu_bp_refcount) {
		struct registry_chunk *chunk, *tmp;
		int ret;

		cds_list_for_each_entry_safe(chunk, tmp,
				&registry_arena.chunk_list, node) {
			munmap(chunk, chunk->data_len
					+ sizeof(struct registry_chunk));
		}
		ret = pthread_key_delete(urcu_bp_key);
		if (ret)
			abort();
	}
	mutex_unlock(&init_lock);
}

/*
 * Keep ABI compability within stable versions. This has never been
 * exposed through a header, but needs to stay in the .so until the
 * soname is bumped.
 */
void rcu_bp_exit(void)
{
}

/*
 * Holding the rcu_gp_lock and rcu_registry_lock across fork will make
 * sure we fork() don't race with a concurrent thread executing with
 * any of those locks held. This ensures that the registry and data
 * protected by rcu_gp_lock are in a coherent state in the child.
 */
void rcu_bp_before_fork(void)
{
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	assert(!ret);
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	assert(!ret);
	mutex_lock(&rcu_gp_lock);
	mutex_lock(&rcu_registry_lock);
	saved_fork_signal_mask = oldmask;
}

void rcu_bp_after_fork_parent(void)
{
	sigset_t oldmask;
	int ret;

	oldmask = saved_fork_signal_mask;
	mutex_unlock(&rcu_registry_lock);
	mutex_unlock(&rcu_gp_lock);
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	assert(!ret);
}

/*
 * Prune all entries from registry except our own thread. Fits the Linux
 * fork behavior. Called with rcu_gp_lock and rcu_registry_lock held.
 */
static
void urcu_bp_prune_registry(void)
{
	struct registry_chunk *chunk;
	struct rcu_reader *rcu_reader_reg;

	cds_list_for_each_entry(chunk, &registry_arena.chunk_list, node) {
		for (rcu_reader_reg = (struct rcu_reader *) &chunk->data[0];
				rcu_reader_reg < (struct rcu_reader *) &chunk->data[chunk->data_len];
				rcu_reader_reg++) {
			if (!rcu_reader_reg->alloc)
				continue;
			if (rcu_reader_reg->tid == pthread_self())
				continue;
			cleanup_thread(chunk, rcu_reader_reg);
		}
	}
}

void rcu_bp_after_fork_child(void)
{
	sigset_t oldmask;
	int ret;

	urcu_bp_prune_registry();
	oldmask = saved_fork_signal_mask;
	mutex_unlock(&rcu_registry_lock);
	mutex_unlock(&rcu_gp_lock);
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	assert(!ret);
}

void *rcu_dereference_sym_bp(void *p)
{
	return _rcu_dereference(p);
}

void *rcu_set_pointer_sym_bp(void **p, void *v)
{
	cmm_wmb();
	uatomic_set(p, v);
	return v;
}

void *rcu_xchg_pointer_sym_bp(void **p, void *v)
{
	cmm_wmb();
	return uatomic_xchg(p, v);
}

void *rcu_cmpxchg_pointer_sym_bp(void **p, void *old, void *_new)
{
	cmm_wmb();
	return uatomic_cmpxchg(p, old, _new);
}

DEFINE_RCU_FLAVOR(rcu_flavor);

#include "urcu-call-rcu-impl.h"
#include "urcu-defer-impl.h"
