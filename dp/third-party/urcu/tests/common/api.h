#ifndef _INCLUDE_API_H
#define _INCLUDE_API_H

#define _GNU_SOURCE
#include "config.h"

/*
 * common.h: Common Linux kernel-isms.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; but version 2 of the License only due
 * to code included from the Linux kernel.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (c) 2006 Paul E. McKenney, IBM.
 *
 * Much code taken from the Linux kernel.  For such code, the option
 * to redistribute under later versions of GPL might not be available.
 */

#include <urcu/compiler.h>
#include <urcu/arch.h>
#include "cpuset.h"

/*
 * Machine parameters.
 */

#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(CAA_CACHE_LINE_SIZE)))

/*
 * api_pthreads.h: API mapping to pthreads environment.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.  However, please note that much
 * of the code in this file derives from the Linux kernel, and that such
 * code may not be available except under GPLv2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (c) 2006 Paul E. McKenney, IBM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/param.h>
/* #include "atomic.h" */

/*
 * Exclusive locking primitives.
 */

typedef pthread_mutex_t spinlock_t;

#define DEFINE_SPINLOCK(lock) spinlock_t lock = PTHREAD_MUTEX_INITIALIZER;
#define __SPIN_LOCK_UNLOCKED(lockp) PTHREAD_MUTEX_INITIALIZER

static void spin_lock_init(spinlock_t *sp)
{
	if (pthread_mutex_init(sp, NULL) != 0) {
		perror("spin_lock_init:pthread_mutex_init");
		exit(-1);
	}
}

static void spin_lock(spinlock_t *sp)
{
	if (pthread_mutex_lock(sp) != 0) {
		perror("spin_lock:pthread_mutex_lock");
		exit(-1);
	}
}

static void spin_unlock(spinlock_t *sp)
{
	if (pthread_mutex_unlock(sp) != 0) {
		perror("spin_unlock:pthread_mutex_unlock");
		exit(-1);
	}
}

#define spin_lock_irqsave(l, f) do { f = 1; spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l, f) do { f = 0; spin_unlock(l); } while (0)

/*
 * Thread creation/destruction primitives.
 */

typedef pthread_t thread_id_t;

#define NR_THREADS 128

#define __THREAD_ID_MAP_EMPTY ((thread_id_t) 0)
#define __THREAD_ID_MAP_WAITING ((thread_id_t) 1)
thread_id_t __thread_id_map[NR_THREADS];
spinlock_t __thread_id_map_mutex;

#define for_each_thread(t) \
	for (t = 0; t < NR_THREADS; t++)

#define for_each_running_thread(t) \
	for (t = 0; t < NR_THREADS; t++) \
		if ((__thread_id_map[t] != __THREAD_ID_MAP_EMPTY) && \
		    (__thread_id_map[t] != __THREAD_ID_MAP_WAITING))

#define for_each_tid(t, tid) \
	for (t = 0; t < NR_THREADS; t++) \
		if ((((tid) = __thread_id_map[t]) != __THREAD_ID_MAP_EMPTY) && \
		    ((tid) != __THREAD_ID_MAP_WAITING))

pthread_key_t thread_id_key;

static int __smp_thread_id(void)
{
	int i;
	thread_id_t tid = pthread_self();

	for (i = 0; i < NR_THREADS; i++) {
		if (__thread_id_map[i] == tid) {
			long v = i + 1;  /* must be non-NULL. */

			if (pthread_setspecific(thread_id_key, (void *)v) != 0) {
				perror("pthread_setspecific");
				exit(-1);
			}
			return i;
		}
	}
	spin_lock(&__thread_id_map_mutex);
	for (i = 0; i < NR_THREADS; i++) {
		if (__thread_id_map[i] == tid) {
			spin_unlock(&__thread_id_map_mutex);
			return i;
		}
	}
	spin_unlock(&__thread_id_map_mutex);
	fprintf(stderr, "smp_thread_id: Rogue thread, id: %lu(%#lx)\n",
			(unsigned long) tid, (unsigned long) tid);
	exit(-1);
}

static int smp_thread_id(void)
{
	void *id;

	id = pthread_getspecific(thread_id_key);
	if (id == NULL)
		return __smp_thread_id();
	return (long)(id - 1);
}

static thread_id_t create_thread(void *(*func)(void *), void *arg)
{
	thread_id_t tid;
	int i;

	spin_lock(&__thread_id_map_mutex);
	for (i = 0; i < NR_THREADS; i++) {
		if (__thread_id_map[i] == __THREAD_ID_MAP_EMPTY)
			break;
	}
	if (i >= NR_THREADS) {
		spin_unlock(&__thread_id_map_mutex);
		fprintf(stderr, "Thread limit of %d exceeded!\n", NR_THREADS);
		exit(-1);
	}
	__thread_id_map[i] = __THREAD_ID_MAP_WAITING;
	spin_unlock(&__thread_id_map_mutex);
	if (pthread_create(&tid, NULL, func, arg) != 0) {
		perror("create_thread:pthread_create");
		exit(-1);
	}
	__thread_id_map[i] = tid;
	return tid;
}

static void *wait_thread(thread_id_t tid)
{
	int i;
	void *vp;

	for (i = 0; i < NR_THREADS; i++) {
		if (__thread_id_map[i] == tid)
			break;
	}
	if (i >= NR_THREADS){
		fprintf(stderr, "wait_thread: bad tid = %lu(%#lx)\n",
				(unsigned long)tid, (unsigned long)tid);
		exit(-1);
	}
	if (pthread_join(tid, &vp) != 0) {
		perror("wait_thread:pthread_join");
		exit(-1);
	}
	__thread_id_map[i] = __THREAD_ID_MAP_EMPTY;
	return vp;
}

static void wait_all_threads(void)
{
	int i;
	thread_id_t tid;

	for (i = 1; i < NR_THREADS; i++) {
		tid = __thread_id_map[i];
		if (tid != __THREAD_ID_MAP_EMPTY &&
		    tid != __THREAD_ID_MAP_WAITING)
			(void)wait_thread(tid);
	}
}

static void run_on(int cpu)
{
#if HAVE_SCHED_SETAFFINITY
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
#if SCHED_SETAFFINITY_ARGS == 2
	sched_setaffinity(0, &mask);
#else
	sched_setaffinity(0, sizeof(mask), &mask);
#endif
#endif /* HAVE_SCHED_SETAFFINITY */
}

/*
 * timekeeping -- very crude -- should use MONOTONIC...
 */

long long get_microseconds(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		abort();
	return ((long long)tv.tv_sec) * 1000000LL + (long long)tv.tv_usec;
}

/*
 * Per-thread variables.
 */

#define DEFINE_PER_THREAD(type, name) \
	struct { \
		__typeof__(type) v \
			__attribute__((__aligned__(CAA_CACHE_LINE_SIZE))); \
	} __per_thread_##name[NR_THREADS];
#define DECLARE_PER_THREAD(type, name) extern DEFINE_PER_THREAD(type, name)

#define per_thread(name, thread) __per_thread_##name[thread].v
#define __get_thread_var(name) per_thread(name, smp_thread_id())

#define init_per_thread(name, v) \
	do { \
		int __i_p_t_i; \
		for (__i_p_t_i = 0; __i_p_t_i < NR_THREADS; __i_p_t_i++) \
			per_thread(name, __i_p_t_i) = v; \
	} while (0)

DEFINE_PER_THREAD(int, smp_processor_id);

/*
 * Bug checks.
 */

#define BUG_ON(c) do { if (!(c)) abort(); } while (0)

/*
 * Initialization -- Must be called before calling any primitives.
 */

static void smp_init(void)
{
	int i;

	spin_lock_init(&__thread_id_map_mutex);
	__thread_id_map[0] = pthread_self();
	for (i = 1; i < NR_THREADS; i++)
		__thread_id_map[i] = __THREAD_ID_MAP_EMPTY;
	init_per_thread(smp_processor_id, 0);
	if (pthread_key_create(&thread_id_key, NULL) != 0) {
		perror("pthread_key_create");
		exit(-1);
	}
}

#endif
