/*
 * test_looplen.c
 *
 * Userspace RCU library - test program
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

#define _GNU_SOURCE
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

#ifndef DYNAMIC_LINK_TEST
#define _LGPL_SOURCE
#else
#define debug_yield_read()
#endif
#include <urcu.h>

static inline void loop_sleep(unsigned long loops)
{
	while (loops-- != 0)
		caa_cpu_relax();
}

#define LOOPS 1048576
#define TESTS 10

int main(int argc, char **argv)
{
	unsigned long i;
	cycles_t time1, time2;
	cycles_t time_tot = 0;
	double cpl;

	for (i = 0; i < TESTS; i++) {
		time1 = caa_get_cycles();
		loop_sleep(LOOPS);
		time2 = caa_get_cycles();
		time_tot += time2 - time1;
	}
	cpl = ((double)time_tot) / (double)TESTS / (double)LOOPS;

	printf("CALIBRATION : %g cycles per loop\n", cpl);
	printf("time_tot = %llu, LOOPS = %d, TESTS = %d\n",
	       time_tot, LOOPS, TESTS);

	return 0;
}
