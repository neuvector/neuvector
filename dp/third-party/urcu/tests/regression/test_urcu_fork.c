/*
 * test_urcu_fork.c
 *
 * Userspace RCU library - test program (fork)
 *
 * Copyright February 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <sched.h>
#include <errno.h>

#include <urcu/arch.h>
#include <urcu/tls-compat.h>

#ifndef DYNAMIC_LINK_TEST
#define _LGPL_SOURCE
#else
#define rcu_debug_yield_read()
#endif
#include <urcu.h>

struct test_node {
	int somedata;
	struct rcu_head head;
};

static void cb(struct rcu_head *head)
{
	struct test_node *node;

	fprintf(stderr, "rcu callback invoked in pid: %d\n",
		(int) getpid());
	node = caa_container_of(head, struct test_node, head);
	free(node);
}

static void test_rcu(void)
{
	struct test_node *node;

	rcu_register_thread();

	synchronize_rcu();

	rcu_read_lock();
	rcu_read_unlock();

	node = malloc(sizeof(*node));
	assert(node);

	call_rcu(&node->head, cb);

	synchronize_rcu();

	rcu_unregister_thread();
}

int main(int argc, char **argv)
{
	pid_t pid;
	int ret;

#if 0
	/* pthread_atfork does not work with malloc/free in callbacks */
	ret = pthread_atfork(call_rcu_before_fork,
		call_rcu_after_fork_parent,
		call_rcu_after_fork_child);
	if (ret) {
		errno = ret;
		perror("pthread_atfork");
		exit(EXIT_FAILURE);
	}
#endif

	test_rcu();

	synchronize_rcu();

	fprintf(stderr, "%s parent pid: %d, before fork\n",
		argv[0], (int) getpid());

	call_rcu_before_fork();
	pid = fork();

	if (pid == 0) {
		/* child */
		call_rcu_after_fork_child();
		fprintf(stderr, "%s child pid: %d, after fork\n",
			argv[0], (int) getpid());
		test_rcu();
		fprintf(stderr, "%s child pid: %d, after rcu test\n",
			argv[0], (int) getpid());
	} else if (pid > 0) {
		int status;

		/* parent */
		call_rcu_after_fork_parent();
		fprintf(stderr, "%s parent pid: %d, after fork\n",
			argv[0], (int) getpid());
		test_rcu();
		fprintf(stderr, "%s parent pid: %d, after rcu test\n",
			argv[0], (int) getpid());
		for (;;) {
			pid = wait(&status);
			if (WIFEXITED(status)) {
				fprintf(stderr, "child %u exited normally with status %u\n",
					pid, WEXITSTATUS(status));
				break;
			} else if (WIFSIGNALED(status)) {
				fprintf(stderr, "child %u was terminated by signal %u\n",
					pid, WTERMSIG(status));
				break;
			} else {
				continue;
			}
		}
	} else {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
