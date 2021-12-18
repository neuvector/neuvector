/*
 * test_urcu_wfcq.c
 *
 * Userspace RCU library - example RCU-based lock-free concurrent queue
 *
 * Copyright February 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright February 2010 - Paolo Bonzini <pbonzini@redhat.com>
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

#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <urcu/arch.h>
#include <urcu/tls-compat.h>
#include <urcu/uatomic.h>
#include "cpuset.h"
#include "thread-id.h"

/* hardcoded number of CPUs */
#define NR_CPUS 16384

#ifndef DYNAMIC_LINK_TEST
#define _LGPL_SOURCE
#endif
#include <urcu/wfcqueue.h>

enum test_sync {
	TEST_SYNC_NONE = 0,
	TEST_SYNC_MUTEX,
};

static enum test_sync test_sync;

static int test_force_sync;

static volatile int test_go, test_stop_enqueue, test_stop_dequeue;

static unsigned long rduration;

static unsigned long duration;

/* read-side C.S. duration, in loops */
static unsigned long wdelay;

static inline void loop_sleep(unsigned long loops)
{
	while (loops-- != 0)
		caa_cpu_relax();
}

static int verbose_mode;

static int test_dequeue, test_splice, test_wait_empty;
static int test_enqueue_stopped;

#define printf_verbose(fmt, args...)		\
	do {					\
		if (verbose_mode)		\
			printf(fmt, ## args);	\
	} while (0)

static unsigned int cpu_affinities[NR_CPUS];
static unsigned int next_aff = 0;
static int use_affinity = 0;

pthread_mutex_t affinity_mutex = PTHREAD_MUTEX_INITIALIZER;

static void set_affinity(void)
{
#if HAVE_SCHED_SETAFFINITY
	cpu_set_t mask;
	int cpu, ret;
#endif /* HAVE_SCHED_SETAFFINITY */

	if (!use_affinity)
		return;

#if HAVE_SCHED_SETAFFINITY
	ret = pthread_mutex_lock(&affinity_mutex);
	if (ret) {
		perror("Error in pthread mutex lock");
		exit(-1);
	}
	cpu = cpu_affinities[next_aff++];
	ret = pthread_mutex_unlock(&affinity_mutex);
	if (ret) {
		perror("Error in pthread mutex unlock");
		exit(-1);
	}

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
 * returns 0 if test should end.
 */
static int test_duration_dequeue(void)
{
	return !test_stop_dequeue;
}

static int test_duration_enqueue(void)
{
	return !test_stop_enqueue;
}

static DEFINE_URCU_TLS(unsigned long long, nr_dequeues);
static DEFINE_URCU_TLS(unsigned long long, nr_enqueues);

static DEFINE_URCU_TLS(unsigned long long, nr_successful_dequeues);
static DEFINE_URCU_TLS(unsigned long long, nr_successful_enqueues);
static DEFINE_URCU_TLS(unsigned long long, nr_empty_dest_enqueues);
static DEFINE_URCU_TLS(unsigned long long, nr_splice);
static DEFINE_URCU_TLS(unsigned long long, nr_dequeue_last);

static unsigned int nr_enqueuers;
static unsigned int nr_dequeuers;

static struct cds_wfcq_head __attribute__((aligned(CAA_CACHE_LINE_SIZE))) head;
static struct cds_wfcq_tail __attribute__((aligned(CAA_CACHE_LINE_SIZE))) tail;

static void *thr_enqueuer(void *_count)
{
	unsigned long long *count = _count;
	bool was_nonempty;

	printf_verbose("thread_begin %s, tid %lu\n",
			"enqueuer", urcu_get_thread_id());

	set_affinity();

	while (!test_go)
	{
	}
	cmm_smp_mb();

	for (;;) {
		struct cds_wfcq_node *node = malloc(sizeof(*node));
		if (!node)
			goto fail;
		cds_wfcq_node_init(node);
		was_nonempty = cds_wfcq_enqueue(&head, &tail, node);
		URCU_TLS(nr_successful_enqueues)++;
		if (!was_nonempty)
			URCU_TLS(nr_empty_dest_enqueues)++;

		if (caa_unlikely(wdelay))
			loop_sleep(wdelay);
fail:
		URCU_TLS(nr_enqueues)++;
		if (caa_unlikely(!test_duration_enqueue()))
			break;
	}

	uatomic_inc(&test_enqueue_stopped);
	count[0] = URCU_TLS(nr_enqueues);
	count[1] = URCU_TLS(nr_successful_enqueues);
	count[2] = URCU_TLS(nr_empty_dest_enqueues);
	printf_verbose("enqueuer thread_end, tid %lu, "
			"enqueues %llu successful_enqueues %llu, "
			"empty_dest_enqueues %llu\n",
			urcu_get_thread_id(),
			URCU_TLS(nr_enqueues),
			URCU_TLS(nr_successful_enqueues),
			URCU_TLS(nr_empty_dest_enqueues));
	return ((void*)1);

}

static void do_test_dequeue(enum test_sync sync)
{
	struct cds_wfcq_node *node;
	int state;

	if (sync == TEST_SYNC_MUTEX)
		node = cds_wfcq_dequeue_with_state_blocking(&head, &tail,
				&state);
	else
		node = __cds_wfcq_dequeue_with_state_blocking(&head, &tail,
				&state);

	if (state & CDS_WFCQ_STATE_LAST)
		URCU_TLS(nr_dequeue_last)++;

	if (node) {
		free(node);
		URCU_TLS(nr_successful_dequeues)++;
	}
	URCU_TLS(nr_dequeues)++;
}

static void do_test_splice(enum test_sync sync)
{
	struct cds_wfcq_head tmp_head;
	struct cds_wfcq_tail tmp_tail;
	struct cds_wfcq_node *node, *n;
	enum cds_wfcq_ret ret;

	cds_wfcq_init(&tmp_head, &tmp_tail);

	if (sync == TEST_SYNC_MUTEX)
		ret = cds_wfcq_splice_blocking(&tmp_head, &tmp_tail,
			&head, &tail);
	else
		ret = __cds_wfcq_splice_blocking(&tmp_head, &tmp_tail,
			&head, &tail);

	switch (ret) {
	case CDS_WFCQ_RET_WOULDBLOCK:
		assert(0);	/* blocking call */
		break;
	case CDS_WFCQ_RET_DEST_EMPTY:
		URCU_TLS(nr_splice)++;
		URCU_TLS(nr_dequeue_last)++;
		/* ok */
		break;
	case CDS_WFCQ_RET_DEST_NON_EMPTY:
		assert(0);	/* entirely unexpected */
		break;
	case CDS_WFCQ_RET_SRC_EMPTY:
		/* ok, we could even skip iteration on dest if we wanted */
		break;
	}

	__cds_wfcq_for_each_blocking_safe(&tmp_head, &tmp_tail, node, n) {
		free(node);
		URCU_TLS(nr_successful_dequeues)++;
		URCU_TLS(nr_dequeues)++;
	}
}

static void *thr_dequeuer(void *_count)
{
	unsigned long long *count = _count;
	unsigned int counter = 0;

	printf_verbose("thread_begin %s, tid %lu\n",
			"dequeuer", urcu_get_thread_id());

	set_affinity();

	while (!test_go)
	{
	}
	cmm_smp_mb();

	for (;;) {
		if (test_dequeue && test_splice) {
			if (counter & 1)
				do_test_dequeue(test_sync);
			else
				do_test_splice(test_sync);
			counter++;
		} else {
			if (test_dequeue)
				do_test_dequeue(test_sync);
			else
				do_test_splice(test_sync);
		}
		if (caa_unlikely(!test_duration_dequeue()))
			break;
		if (caa_unlikely(rduration))
			loop_sleep(rduration);
	}

	printf_verbose("dequeuer thread_end, tid %lu, "
			"dequeues %llu, successful_dequeues %llu, "
			"nr_splice %llu\n",
			urcu_get_thread_id(),
			URCU_TLS(nr_dequeues), URCU_TLS(nr_successful_dequeues),
			URCU_TLS(nr_splice));
	count[0] = URCU_TLS(nr_dequeues);
	count[1] = URCU_TLS(nr_successful_dequeues);
	count[2] = URCU_TLS(nr_splice);
	count[3] = URCU_TLS(nr_dequeue_last);
	return ((void*)2);
}

static void test_end(unsigned long long *nr_dequeues,
		unsigned long long *nr_dequeue_last)
{
	struct cds_wfcq_node *node;
	int state;

	do {
		node = cds_wfcq_dequeue_with_state_blocking(&head, &tail,
				&state);
		if (node) {
			if (state & CDS_WFCQ_STATE_LAST)
				(*nr_dequeue_last)++;
			free(node);
			(*nr_dequeues)++;
		}
	} while (node);
}

static void show_usage(int argc, char **argv)
{
	printf("Usage : %s nr_dequeuers nr_enqueuers duration (s) <OPTIONS>\n",
		argv[0]);
	printf("OPTIONS:\n");
	printf("	[-d delay] (enqueuer period (in loops))\n");
	printf("	[-c duration] (dequeuer period (in loops))\n");
	printf("	[-v] (verbose output)\n");
	printf("	[-a cpu#] [-a cpu#]... (affinity)\n");
	printf("	[-q] (test dequeue)\n");
	printf("	[-s] (test splice, enabled by default)\n");
	printf("	[-M] (use mutex external synchronization)\n");
	printf("		Note: default: no external synchronization used.\n");
	printf("	[-f] (force user-provided synchronization)\n");
	printf("	[-w] Wait for dequeuer to empty queue\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	int err;
	pthread_t *tid_enqueuer, *tid_dequeuer;
	void *tret;
	unsigned long long *count_enqueuer, *count_dequeuer;
	unsigned long long tot_enqueues = 0, tot_dequeues = 0;
	unsigned long long tot_successful_enqueues = 0,
			   tot_successful_dequeues = 0,
			   tot_empty_dest_enqueues = 0,
			   tot_splice = 0, tot_dequeue_last = 0;
	unsigned long long end_dequeues = 0;
	int i, a, retval = 0;

	if (argc < 4) {
		show_usage(argc, argv);
		return -1;
	}

	err = sscanf(argv[1], "%u", &nr_dequeuers);
	if (err != 1) {
		show_usage(argc, argv);
		return -1;
	}

	err = sscanf(argv[2], "%u", &nr_enqueuers);
	if (err != 1) {
		show_usage(argc, argv);
		return -1;
	}
	
	err = sscanf(argv[3], "%lu", &duration);
	if (err != 1) {
		show_usage(argc, argv);
		return -1;
	}

	for (i = 4; i < argc; i++) {
		if (argv[i][0] != '-')
			continue;
		switch (argv[i][1]) {
		case 'a':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			a = atoi(argv[++i]);
			cpu_affinities[next_aff++] = a;
			use_affinity = 1;
			printf_verbose("Adding CPU %d affinity\n", a);
			break;
		case 'c':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			rduration = atol(argv[++i]);
			break;
		case 'd':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			wdelay = atol(argv[++i]);
			break;
		case 'v':
			verbose_mode = 1;
			break;
		case 'q':
			test_dequeue = 1;
			break;
		case 's':
			test_splice = 1;
			break;
		case 'M':
			test_sync = TEST_SYNC_MUTEX;
			break;
		case 'w':
			test_wait_empty = 1;
			break;
		case 'f':
			test_force_sync = 1;
			break;
		}
	}

	/* activate splice test by default */
	if (!test_dequeue && !test_splice)
		test_splice = 1;

	if (test_sync == TEST_SYNC_NONE && nr_dequeuers > 1 && test_dequeue) {
		if (test_force_sync) {
			fprintf(stderr, "[WARNING] Using dequeue concurrently "
				"with other dequeue or splice without external "
				"synchronization. Expect run-time failure.\n");
		} else {
			printf("Enforcing mutex synchronization\n");
			test_sync = TEST_SYNC_MUTEX;
		}
	}

	printf_verbose("running test for %lu seconds, %u enqueuers, "
		       "%u dequeuers.\n",
		       duration, nr_enqueuers, nr_dequeuers);
	if (test_dequeue)
		printf_verbose("dequeue test activated.\n");
	else
		printf_verbose("splice test activated.\n");
	if (test_sync == TEST_SYNC_MUTEX)
		printf_verbose("External sync: mutex.\n");
	else
		printf_verbose("External sync: none.\n");
	if (test_wait_empty)
		printf_verbose("Wait for dequeuers to empty queue.\n");
	printf_verbose("Writer delay : %lu loops.\n", rduration);
	printf_verbose("Reader duration : %lu loops.\n", wdelay);
	printf_verbose("thread %-6s, tid %lu\n",
			"main", urcu_get_thread_id());

	tid_enqueuer = calloc(nr_enqueuers, sizeof(*tid_enqueuer));
	tid_dequeuer = calloc(nr_dequeuers, sizeof(*tid_dequeuer));
	count_enqueuer = calloc(nr_enqueuers, 3 * sizeof(*count_enqueuer));
	count_dequeuer = calloc(nr_dequeuers, 4 * sizeof(*count_dequeuer));
	cds_wfcq_init(&head, &tail);

	next_aff = 0;

	for (i = 0; i < nr_enqueuers; i++) {
		err = pthread_create(&tid_enqueuer[i], NULL, thr_enqueuer,
				     &count_enqueuer[3 * i]);
		if (err != 0)
			exit(1);
	}
	for (i = 0; i < nr_dequeuers; i++) {
		err = pthread_create(&tid_dequeuer[i], NULL, thr_dequeuer,
				     &count_dequeuer[4 * i]);
		if (err != 0)
			exit(1);
	}

	cmm_smp_mb();

	test_go = 1;

	for (i = 0; i < duration; i++) {
		sleep(1);
		if (verbose_mode)
			write (1, ".", 1);
	}

	test_stop_enqueue = 1;

	if (test_wait_empty) {
		while (nr_enqueuers != uatomic_read(&test_enqueue_stopped)) {
			sleep(1);
		}
		while (!cds_wfcq_empty(&head, &tail)) {
			sleep(1);
		}
	}

	test_stop_dequeue = 1;

	for (i = 0; i < nr_enqueuers; i++) {
		err = pthread_join(tid_enqueuer[i], &tret);
		if (err != 0)
			exit(1);
		tot_enqueues += count_enqueuer[3 * i];
		tot_successful_enqueues += count_enqueuer[3 * i + 1];
		tot_empty_dest_enqueues += count_enqueuer[3 * i + 2];
	}
	for (i = 0; i < nr_dequeuers; i++) {
		err = pthread_join(tid_dequeuer[i], &tret);
		if (err != 0)
			exit(1);
		tot_dequeues += count_dequeuer[4 * i];
		tot_successful_dequeues += count_dequeuer[4 * i + 1];
		tot_splice += count_dequeuer[4 * i + 2];
		tot_dequeue_last += count_dequeuer[4 * i + 3];
	}
	
	test_end(&end_dequeues, &tot_dequeue_last);

	printf_verbose("total number of enqueues : %llu, dequeues %llu\n",
		       tot_enqueues, tot_dequeues);
	printf_verbose("total number of successful enqueues : %llu, "
		       "enqueues to empty dest : %llu, "
		       "successful dequeues %llu, "
		       "splice : %llu, dequeue_last : %llu\n",
		       tot_successful_enqueues,
		       tot_empty_dest_enqueues,
		       tot_successful_dequeues,
		       tot_splice, tot_dequeue_last);
	printf("SUMMARY %-25s testdur %4lu nr_enqueuers %3u wdelay %6lu "
		"nr_dequeuers %3u "
		"rdur %6lu nr_enqueues %12llu nr_dequeues %12llu "
		"successful enqueues %12llu enqueues to empty dest %12llu "
		"successful dequeues %12llu splice %12llu "
		"dequeue_last %llu "
		"end_dequeues %llu nr_ops %12llu\n",
		argv[0], duration, nr_enqueuers, wdelay,
		nr_dequeuers, rduration, tot_enqueues, tot_dequeues,
		tot_successful_enqueues,
		tot_empty_dest_enqueues,
		tot_successful_dequeues, tot_splice, tot_dequeue_last,
		end_dequeues,
		tot_enqueues + tot_dequeues);

	if (tot_successful_enqueues != tot_successful_dequeues + end_dequeues) {
		printf("WARNING! Discrepancy between nr succ. enqueues %llu vs "
		       "succ. dequeues + end dequeues %llu.\n",
		       tot_successful_enqueues,
		       tot_successful_dequeues + end_dequeues);
		retval = 1;
	}

	/*
	 * If only using splice to dequeue, the enqueuer should see
	 * exactly as many empty queues than the number of non-empty
	 * src splice.
	 */
	if (tot_empty_dest_enqueues != tot_dequeue_last) {
		printf("WARNING! Discrepancy between empty enqueue (%llu) and "
			"number of dequeue of last element (%llu)\n",
			tot_empty_dest_enqueues,
			tot_dequeue_last);
		retval = 1;
	}
	free(count_enqueuer);
	free(count_dequeuer);
	free(tid_enqueuer);
	free(tid_dequeuer);
	return retval;
}
