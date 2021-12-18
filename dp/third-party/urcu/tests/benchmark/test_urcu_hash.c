/*
 * test_urcu_hash.c
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

#define _GNU_SOURCE
#include "test_urcu_hash.h"

enum test_hash {
	TEST_HASH_RW,
	TEST_HASH_UNIQUE,
};

struct test_hash_cb {
	void (*sigusr1)(int signo);
	void (*sigusr2)(int signo);
	void *(*thr_reader)(void *_count);
	void *(*thr_writer)(void *_count);
	int (*populate_hash)(void);
};

static
struct test_hash_cb test_hash_cb[] = {
	[TEST_HASH_RW] = {
		test_hash_rw_sigusr1_handler,
		test_hash_rw_sigusr2_handler,
		test_hash_rw_thr_reader,
		test_hash_rw_thr_writer,
		test_hash_rw_populate_hash,
	},
	[TEST_HASH_UNIQUE] = {
		test_hash_unique_sigusr1_handler,
		test_hash_unique_sigusr2_handler,
		test_hash_unique_thr_reader,
		test_hash_unique_thr_writer,
		test_hash_unique_populate_hash,
	},

};

static enum test_hash test_choice = TEST_HASH_RW;

void (*get_sigusr1_cb(void))(int)
{
	return test_hash_cb[test_choice].sigusr1;
}

void (*get_sigusr2_cb(void))(int)
{
	return test_hash_cb[test_choice].sigusr2;
}

void *(*get_thr_reader_cb(void))(void *)
{
	return test_hash_cb[test_choice].thr_reader;
}

void *(*get_thr_writer_cb(void))(void *)
{
	return test_hash_cb[test_choice].thr_writer;
}

int (*get_populate_hash_cb(void))(void)
{
	return test_hash_cb[test_choice].populate_hash;
}

__DEFINE_URCU_TLS_GLOBAL(unsigned int, rand_lookup);
__DEFINE_URCU_TLS_GLOBAL(unsigned long, nr_add);
__DEFINE_URCU_TLS_GLOBAL(unsigned long, nr_addexist);
__DEFINE_URCU_TLS_GLOBAL(unsigned long, nr_del);
__DEFINE_URCU_TLS_GLOBAL(unsigned long, nr_delnoent);
__DEFINE_URCU_TLS_GLOBAL(unsigned long, lookup_fail);
__DEFINE_URCU_TLS_GLOBAL(unsigned long, lookup_ok);

struct cds_lfht *test_ht;

volatile int test_go, test_stop;

unsigned long wdelay;

unsigned long duration;

/* read-side C.S. duration, in loops */
unsigned long rduration;

unsigned long init_hash_size = DEFAULT_HASH_SIZE;
unsigned long min_hash_alloc_size = DEFAULT_MIN_ALLOC_SIZE;
unsigned long max_hash_buckets_size = (1UL << 20);
unsigned long init_populate;
int opt_auto_resize;
int add_only, add_unique, add_replace;
const struct cds_lfht_mm_type *memory_backend;

unsigned long init_pool_offset, lookup_pool_offset, write_pool_offset;
unsigned long init_pool_size = DEFAULT_RAND_POOL,
	lookup_pool_size = DEFAULT_RAND_POOL,
	write_pool_size = DEFAULT_RAND_POOL;
int validate_lookup;
unsigned long nr_hash_chains;	/* 0: normal table, other: number of hash chains */

int count_pipe[2];

int verbose_mode;

unsigned int cpu_affinities[NR_CPUS];
unsigned int next_aff = 0;
int use_affinity = 0;

pthread_mutex_t affinity_mutex = PTHREAD_MUTEX_INITIALIZER;

DEFINE_URCU_TLS(unsigned long long, nr_writes);
DEFINE_URCU_TLS(unsigned long long, nr_reads);

unsigned int nr_readers;
unsigned int nr_writers;

static pthread_mutex_t rcu_copy_mutex = PTHREAD_MUTEX_INITIALIZER;

void set_affinity(void)
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

void rcu_copy_mutex_lock(void)
{
	int ret;
	ret = pthread_mutex_lock(&rcu_copy_mutex);
	if (ret) {
		perror("Error in pthread mutex lock");
		exit(-1);
	}
}

void rcu_copy_mutex_unlock(void)
{
	int ret;

	ret = pthread_mutex_unlock(&rcu_copy_mutex);
	if (ret) {
		perror("Error in pthread mutex unlock");
		exit(-1);
	}
}

unsigned long test_compare(const void *key1, size_t key1_len,
			   const void *key2, size_t key2_len)
{
	if (caa_unlikely(key1_len != key2_len))
		return -1;
	assert(key1_len == sizeof(unsigned long));
	if (key1 == key2)
		return 0;
	else
		return 1;
}

void *thr_count(void *arg)
{
	printf_verbose("thread_begin %s, tid %lu\n",
			"counter", urcu_get_thread_id());

	rcu_register_thread();

	for (;;) {
		unsigned long count;
		long approx_before, approx_after;
		ssize_t len;
		char buf[1];

		rcu_thread_offline();
		len = read(count_pipe[0], buf, 1);
		rcu_thread_online();
		if (caa_unlikely(!test_duration_read()))
			break;
		if (len != 1)
			continue;
		/* Accounting */
		printf("Counting nodes... ");
		fflush(stdout);
		rcu_read_lock();
		cds_lfht_count_nodes(test_ht, &approx_before, &count,
				&approx_after);
		rcu_read_unlock();
		printf("done.\n");
		printf("Approximation before node accounting: %ld nodes.\n",
			approx_before);
		printf("Accounting of nodes in the hash table: "
			"%lu nodes.\n",
			count);
		printf("Approximation after node accounting: %ld nodes.\n",
			approx_after);
	}
	rcu_unregister_thread();
	return NULL;
}

void free_node_cb(struct rcu_head *head)
{
	struct lfht_test_node *node =
		caa_container_of(head, struct lfht_test_node, head);
	free(node);
}

static
void test_delete_all_nodes(struct cds_lfht *ht)
{
	struct cds_lfht_iter iter;
	struct lfht_test_node *node;
	unsigned long count = 0;

	cds_lfht_for_each_entry(ht, &iter, node, node) {
		int ret;

		ret = cds_lfht_del(test_ht, cds_lfht_iter_get_node(&iter));
		assert(!ret);
		call_rcu(&node->head, free_node_cb);
		count++;
	}
	printf("deleted %lu nodes.\n", count);
}

void show_usage(int argc, char **argv)
{
	printf("Usage : %s nr_readers nr_writers duration (s) <OPTIONS>\n",
		argv[0]);
	printf("OPTIONS:\n");
	printf("        [-r] [-w] (yield reader and/or writer)\n");
	printf("        [-d delay] (writer period (us))\n");
	printf("        [-c duration] (reader C.S. duration (in loops))\n");
	printf("        [-v] (verbose output)\n");
	printf("        [-a cpu#] [-a cpu#]... (affinity)\n");
	printf("        [-h size] (initial number of buckets)\n");
	printf("        [-m size] (minimum number of allocated buckets)\n");
	printf("        [-n size] (maximum number of buckets)\n");
printf("        [not -u nor -s] Add entries (supports redundant keys).\n");
	printf("        [-u] Uniquify add (no redundant keys).\n");
	printf("        [-s] Replace (swap) entries.\n");
	printf("        [-i] Add only (no removal).\n");
	printf("        [-k nr_nodes] Number of nodes to insert initially.\n");
	printf("        [-A] Automatically resize hash table.\n");
	printf("        [-B order|chunk|mmap] Specify the memory backend.\n");
	printf("        [-R offset] Lookup pool offset.\n");
	printf("        [-S offset] Write pool offset.\n");
	printf("        [-T offset] Init pool offset.\n");
	printf("        [-M size] Lookup pool size.\n");
	printf("        [-N size] Write pool size.\n");
	printf("        [-O size] Init pool size.\n");
	printf("        [-V] Validate lookups of init values.\n");
	printf("		(use with filled init pool, same lookup range,\n");
	printf("		with different write range)\n");
	printf("	[-U] Uniqueness test.\n");
	printf("	[-C] Number of hash chains.\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	pthread_t *tid_reader, *tid_writer;
	pthread_t tid_count;
	void *tret;
	unsigned long long *count_reader;
	struct wr_count *count_writer;
	unsigned long long tot_reads = 0, tot_writes = 0,
		tot_add = 0, tot_add_exist = 0, tot_remove = 0;
	unsigned long count;
	long approx_before, approx_after;
	int i, a, ret, err, mainret = 0;
	struct sigaction act;
	unsigned int remain;
	unsigned int nr_readers_created = 0, nr_writers_created = 0;
	long long nr_leaked;

	if (argc < 4) {
		show_usage(argc, argv);
		mainret = 1;
		goto end;
	}

	err = sscanf(argv[1], "%u", &nr_readers);
	if (err != 1) {
		show_usage(argc, argv);
		mainret = 1;
		goto end;
	}

	err = sscanf(argv[2], "%u", &nr_writers);
	if (err != 1) {
		show_usage(argc, argv);
		mainret = 1;
		goto end;
	}
	
	err = sscanf(argv[3], "%lu", &duration);
	if (err != 1) {
		show_usage(argc, argv);
		mainret = 1;
		goto end;
	}

	for (i = 4; i < argc; i++) {
		if (argv[i][0] != '-')
			continue;
		switch (argv[i][1]) {
		case 'r':
			rcu_debug_yield_enable(RCU_YIELD_READ);
			break;
		case 'w':
			rcu_debug_yield_enable(RCU_YIELD_WRITE);
			break;
		case 'a':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			a = atoi(argv[++i]);
			cpu_affinities[next_aff++] = a;
			use_affinity = 1;
			printf_verbose("Adding CPU %d affinity\n", a);
			break;
		case 'c':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			rduration = atol(argv[++i]);
			break;
		case 'd':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			wdelay = atol(argv[++i]);
			break;
		case 'v':
			verbose_mode = 1;
			break;
		case 'h':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			init_hash_size = atol(argv[++i]);
			break;
		case 'm':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			min_hash_alloc_size = atol(argv[++i]);
			break;
		case 'n':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			max_hash_buckets_size = atol(argv[++i]);
			break;
		case 'u':
			if (add_replace) {
				printf("Please specify at most one of -s or -u.\n");
				exit(-1);
			}
			add_unique = 1;
			break;
		case 's':
			if (add_unique) {
				printf("Please specify at most one of -s or -u.\n");
				exit(-1);
			}
			add_replace = 1;
			break;
		case 'i':
			add_only = 1;
			break;
		case 'k':
			init_populate = atol(argv[++i]);
			break;
		case 'A':
			opt_auto_resize = 1;
			break;
		case 'B':
			if (argc < i + 2) {
				show_usage(argc, argv);
				mainret = 1;
				goto end;
			}
			i++;
			if (!strcmp("order", argv[i]))
				memory_backend = &cds_lfht_mm_order;
			else if (!strcmp("chunk", argv[i]))
				memory_backend = &cds_lfht_mm_chunk;
			else if (!strcmp("mmap", argv[i]))
				memory_backend = &cds_lfht_mm_mmap;
			else {
				printf("Please specify memory backend with order|chunk|mmap.\n");
				mainret = 1;
				goto end;
			}
			break;
		case 'R':
			lookup_pool_offset = atol(argv[++i]);
			break;
		case 'S':
			write_pool_offset = atol(argv[++i]);
			break;
		case 'T':
			init_pool_offset = atol(argv[++i]);
			break;
		case 'M':
			lookup_pool_size = atol(argv[++i]);
			break;
		case 'N':
			write_pool_size = atol(argv[++i]);
			break;
		case 'O':
			init_pool_size = atol(argv[++i]);
			break;
		case 'V':
			validate_lookup = 1;
			break;
		case 'U':
			test_choice = TEST_HASH_UNIQUE;
			break;
		case 'C':
			nr_hash_chains = atol(argv[++i]);
			break;
		}
	}

	/* Check if hash size is power of 2 */
	if (init_hash_size && init_hash_size & (init_hash_size - 1)) {
		printf("Error: Initial number of buckets (%lu) is not a power of 2.\n",
			init_hash_size);
		mainret = 1;
		goto end;
	}

	if (min_hash_alloc_size && min_hash_alloc_size & (min_hash_alloc_size - 1)) {
		printf("Error: Minimum number of allocated buckets (%lu) is not a power of 2.\n",
			min_hash_alloc_size);
		mainret = 1;
		goto end;
	}

	if (max_hash_buckets_size && max_hash_buckets_size & (max_hash_buckets_size - 1)) {
		printf("Error: Maximum number of buckets (%lu) is not a power of 2.\n",
			max_hash_buckets_size);
		mainret = 1;
		goto end;
	}

	memset(&act, 0, sizeof(act));
	ret = sigemptyset(&act.sa_mask);
	if (ret == -1) {
		perror("sigemptyset");
		mainret = 1;
		goto end;
	}
	act.sa_handler = get_sigusr1_cb();
	act.sa_flags = SA_RESTART;
	ret = sigaction(SIGUSR1, &act, NULL);
	if (ret == -1) {
		perror("sigaction");
		mainret = 1;
		goto end;
	}

	act.sa_handler = get_sigusr2_cb();
	act.sa_flags = SA_RESTART;
	ret = sigaction(SIGUSR2, &act, NULL);
	if (ret == -1) {
		perror("sigaction");
		mainret = 1;
		goto end;
	}

	printf_verbose("running test for %lu seconds, %u readers, %u writers.\n",
		duration, nr_readers, nr_writers);
	printf_verbose("Writer delay : %lu loops.\n", wdelay);
	printf_verbose("Reader duration : %lu loops.\n", rduration);
	printf_verbose("Mode:%s%s.\n",
		add_only ? " add only" : " add/remove",
		add_unique ? " uniquify" : ( add_replace ? " replace" : " insert"));
	printf_verbose("Initial number of buckets: %lu buckets.\n", init_hash_size);
	printf_verbose("Minimum number of allocated buckets: %lu buckets.\n", min_hash_alloc_size);
	printf_verbose("Maximum number of buckets: %lu buckets.\n", max_hash_buckets_size);
	printf_verbose("Init pool size offset %lu size %lu.\n",
		init_pool_offset, init_pool_size);
	printf_verbose("Lookup pool size offset %lu size %lu.\n",
		lookup_pool_offset, lookup_pool_size);
	printf_verbose("Update pool size offset %lu size %lu.\n",
		write_pool_offset, write_pool_size);
	printf_verbose("Number of hash chains: %lu.\n",
		nr_hash_chains);
	printf_verbose("thread %-6s, tid %lu\n",
			"main", urcu_get_thread_id());

	tid_reader = calloc(nr_readers, sizeof(*tid_reader));
	if (!tid_reader) {
		mainret = 1;
		goto end;
	}
	tid_writer = calloc(nr_writers, sizeof(*tid_writer));
	if (!tid_writer) {
		mainret = 1;
		goto end_free_tid_reader;
	}
	count_reader = calloc(nr_readers, sizeof(*count_reader));
	if (!count_reader) {
		mainret = 1;
		goto end_free_tid_writer;
	}
	count_writer = calloc(nr_writers, sizeof(*count_writer));
	if (!count_writer) {
		mainret = 1;
		goto end_free_count_reader;
	}

	err = create_all_cpu_call_rcu_data(0);
	if (err) {
		printf("Per-CPU call_rcu() worker threads unavailable. Using default global worker thread.\n");
	}

	if (memory_backend) {
		test_ht = _cds_lfht_new(init_hash_size, min_hash_alloc_size,
				max_hash_buckets_size,
				(opt_auto_resize ? CDS_LFHT_AUTO_RESIZE : 0) |
				CDS_LFHT_ACCOUNTING, memory_backend,
				&rcu_flavor, NULL);
	} else {
		test_ht = cds_lfht_new(init_hash_size, min_hash_alloc_size,
				max_hash_buckets_size,
				(opt_auto_resize ? CDS_LFHT_AUTO_RESIZE : 0) |
				CDS_LFHT_ACCOUNTING, NULL);
	}
	if (!test_ht) {
		printf("Error allocating hash table.\n");
		mainret = 1;
		goto end_free_call_rcu_data;
	}

	/*
	 * Hash Population needs to be seen as a RCU reader
	 * thread from the point of view of resize.
	 */
	rcu_register_thread();
	ret = (get_populate_hash_cb())();
	assert(!ret);

	rcu_thread_offline();

	next_aff = 0;

	ret = pipe(count_pipe);
	if (ret == -1) {
		perror("pipe");
		mainret = 1;
		goto end_online;
	}

	/* spawn counter thread */
	err = pthread_create(&tid_count, NULL, thr_count,
			     NULL);
	if (err != 0) {
		errno = err;
		mainret = 1;
		perror("pthread_create");
		goto end_close_pipe;
	}

	for (i = 0; i < nr_readers; i++) {
		err = pthread_create(&tid_reader[i],
				     NULL, get_thr_reader_cb(),
				     &count_reader[i]);
		if (err != 0) {
			errno = err;
			mainret = 1;
			perror("pthread_create");
			goto end_pthread_join;
		}
		nr_readers_created++;
	}
	for (i = 0; i < nr_writers; i++) {
		err = pthread_create(&tid_writer[i],
				     NULL, get_thr_writer_cb(),
				     &count_writer[i]);
		if (err != 0) {
			errno = err;
			mainret = 1;
			perror("pthread_create");
			goto end_pthread_join;
		}
		nr_writers_created++;
	}

	cmm_smp_mb();

	test_go = 1;

	remain = duration;
	do {
		remain = sleep(remain);
	} while (remain > 0);

	test_stop = 1;

end_pthread_join:
	for (i = 0; i < nr_readers_created; i++) {
		err = pthread_join(tid_reader[i], &tret);
		if (err != 0) {
			errno = err;
			mainret = 1;
			perror("pthread_join");
		}
		tot_reads += count_reader[i];
	}
	for (i = 0; i < nr_writers_created; i++) {
		err = pthread_join(tid_writer[i], &tret);
		if (err != 0) {
			errno = err;
			mainret = 1;
			perror("pthread_join");
		}
		tot_writes += count_writer[i].update_ops;
		tot_add += count_writer[i].add;
		tot_add_exist += count_writer[i].add_exist;
		tot_remove += count_writer[i].remove;
	}

	/* teardown counter thread */
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_RESTART;
	ret = sigaction(SIGUSR2, &act, NULL);
	if (ret == -1) {
		mainret = 1;
		perror("sigaction");
	}
	{
		char msg[1] = { 0x42 };
		ssize_t ret;

		do {
			ret = write(count_pipe[1], msg, 1);	/* wakeup thread */
		} while (ret == -1L && errno == EINTR);
	}
	err = pthread_join(tid_count, &tret);
	if (err != 0) {
		errno = err;
		mainret = 1;
		perror("pthread_join");
	}

end_close_pipe:
	for (i = 0; i < 2; i++) {
		err = close(count_pipe[i]);
		if (err) {
			mainret = 1;
			perror("close pipe");
		}
	}
	fflush(stdout);
end_online:
	rcu_thread_online();
	rcu_read_lock();
	printf("Counting nodes... ");
	cds_lfht_count_nodes(test_ht, &approx_before, &count, &approx_after);
	printf("done.\n");
	test_delete_all_nodes(test_ht);
	rcu_read_unlock();
	rcu_thread_offline();
	if (count) {
		printf("Approximation before node accounting: %ld nodes.\n",
			approx_before);
		printf("Nodes deleted from hash table before destroy: "
			"%lu nodes.\n",
			count);
		printf("Approximation after node accounting: %ld nodes.\n",
			approx_after);
	}

	ret = cds_lfht_destroy(test_ht, NULL);
	if (ret) {
		printf_verbose("final delete aborted\n");
		mainret = 1;
	} else {
		printf_verbose("final delete success\n");
	}
	printf_verbose("total number of reads : %llu, writes %llu\n", tot_reads,
	       tot_writes);
	nr_leaked = (long long) tot_add + init_populate - tot_remove - count;
	printf("SUMMARY %-25s testdur %4lu nr_readers %3u rdur %6lu "
		"nr_writers %3u "
		"wdelay %6lu nr_reads %12llu nr_writes %12llu nr_ops %12llu "
		"nr_add %12llu nr_add_fail %12llu nr_remove %12llu nr_leaked %12lld\n",
		argv[0], duration, nr_readers, rduration,
		nr_writers, wdelay, tot_reads, tot_writes,
		tot_reads + tot_writes, tot_add, tot_add_exist, tot_remove,
		nr_leaked);
	if (nr_leaked != 0) {
		mainret = 1;
		printf("WARNING: %lld nodes were leaked!\n", nr_leaked);
	}

	rcu_unregister_thread();
end_free_call_rcu_data:
	free_all_cpu_call_rcu_data();
	free(count_writer);
end_free_count_reader:
	free(count_reader);
end_free_tid_writer:
	free(tid_writer);
end_free_tid_reader:
	free(tid_reader);
end:
	if (!mainret)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}
