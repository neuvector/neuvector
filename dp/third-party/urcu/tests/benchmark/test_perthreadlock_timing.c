/*
 * test_perthreadloc_timing.c
 *
 * Per thread locks - test program
 *
 * Copyright February 2009 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>

#include <urcu/arch.h>

#include "thread-id.h"

#include <urcu.h>

struct test_array {
	int a;
};

static struct test_array test_array = { 8 };

struct per_thread_lock {
	pthread_mutex_t lock;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));	/* cache-line aligned */

static struct per_thread_lock *per_thread_lock;

#define OUTER_READ_LOOP	200U
#define INNER_READ_LOOP	100000U
#define READ_LOOP ((unsigned long long)OUTER_READ_LOOP * INNER_READ_LOOP)

#define OUTER_WRITE_LOOP 10U
#define INNER_WRITE_LOOP 200U
#define WRITE_LOOP ((unsigned long long)OUTER_WRITE_LOOP * INNER_WRITE_LOOP)

static int num_read;
static int num_write;

#define NR_READ num_read
#define NR_WRITE num_write

static cycles_t __attribute__((aligned(CAA_CACHE_LINE_SIZE))) *reader_time;
static cycles_t __attribute__((aligned(CAA_CACHE_LINE_SIZE))) *writer_time;

void *thr_reader(void *arg)
{
	int i, j;
	cycles_t time1, time2;
	long tidx = (long)arg;

	printf("thread_begin %s, tid %lu\n",
		"reader", urcu_get_thread_id());
	sleep(2);

	time1 = caa_get_cycles();
	for (i = 0; i < OUTER_READ_LOOP; i++) {
		for (j = 0; j < INNER_READ_LOOP; j++) {
			pthread_mutex_lock(&per_thread_lock[tidx].lock);
			assert(test_array.a == 8);
			pthread_mutex_unlock(&per_thread_lock[tidx].lock);
		}
	}
	time2 = caa_get_cycles();

	reader_time[tidx] = time2 - time1;

	sleep(2);
	printf("thread_end %s, tid %lu\n",
		"reader", urcu_get_thread_id());
	return ((void*)1);

}

void *thr_writer(void *arg)
{
	int i, j;
	long tidx;
	cycles_t time1, time2;

	printf("thread_begin %s, tid %lu\n",
		"writer", urcu_get_thread_id());
	sleep(2);

	for (i = 0; i < OUTER_WRITE_LOOP; i++) {
		for (j = 0; j < INNER_WRITE_LOOP; j++) {
			time1 = caa_get_cycles();
			for (tidx = 0; tidx < NR_READ; tidx++) {
				pthread_mutex_lock(&per_thread_lock[tidx].lock);
			}
			test_array.a = 8;
			for (tidx = NR_READ - 1; tidx >= 0; tidx--) {
				pthread_mutex_unlock(&per_thread_lock[tidx].lock);
			}
			time2 = caa_get_cycles();
			writer_time[(unsigned long)arg] += time2 - time1;
			usleep(1);
		}
	}

	printf("thread_end %s, tid %lu\n",
		"writer", urcu_get_thread_id());
	return ((void*)2);
}

int main(int argc, char **argv)
{
	int err;
	pthread_t *tid_reader, *tid_writer;
	void *tret;
	int i;
	cycles_t tot_rtime = 0;
	cycles_t tot_wtime = 0;

	if (argc < 2) {
		printf("Usage : %s nr_readers nr_writers\n", argv[0]);
		exit(-1);
	}
	num_read = atoi(argv[1]);
	num_write = atoi(argv[2]);

	reader_time = calloc(num_read, sizeof(*reader_time));
	writer_time = calloc(num_write, sizeof(*writer_time));
	tid_reader = calloc(num_read, sizeof(*tid_reader));
	tid_writer = calloc(num_write, sizeof(*tid_writer));

	printf("thread %-6s, tid %lu\n",
		"main", urcu_get_thread_id());

	per_thread_lock = malloc(sizeof(struct per_thread_lock) * NR_READ);

	for (i = 0; i < NR_READ; i++) {
		pthread_mutex_init(&per_thread_lock[i].lock, NULL);
	}
	for (i = 0; i < NR_READ; i++) {
		err = pthread_create(&tid_reader[i], NULL, thr_reader,
				     (void *)(long)i);
		if (err != 0)
			exit(1);
	}
	for (i = 0; i < NR_WRITE; i++) {
		err = pthread_create(&tid_writer[i], NULL, thr_writer,
				     (void *)(long)i);
		if (err != 0)
			exit(1);
	}

	sleep(10);

	for (i = 0; i < NR_READ; i++) {
		err = pthread_join(tid_reader[i], &tret);
		if (err != 0)
			exit(1);
		tot_rtime += reader_time[i];
	}
	for (i = 0; i < NR_WRITE; i++) {
		err = pthread_join(tid_writer[i], &tret);
		if (err != 0)
			exit(1);
		tot_wtime += writer_time[i];
	}
	printf("Time per read : %g cycles\n",
	       (double)tot_rtime / ((double)NR_READ * (double)READ_LOOP));
	printf("Time per write : %g cycles\n",
	       (double)tot_wtime / ((double)NR_WRITE * (double)WRITE_LOOP));
	free(per_thread_lock);

	free(reader_time);
	free(writer_time);
	free(tid_reader);
	free(tid_writer);

	return 0;
}
