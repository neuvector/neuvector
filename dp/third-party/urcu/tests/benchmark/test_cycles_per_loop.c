/*
 * test_cycles_per_loop.c
 *
 * Userspace RCU library - test cycles per loop
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

#include <urcu/arch.h>
#include <stdio.h>

#define NR_LOOPS 1000000UL

static inline void loop_sleep(unsigned long loops)
{
	while (loops-- != 0)
		caa_cpu_relax();
}

int main()
{
	cycles_t time1, time2;

	time1 = caa_get_cycles();
	loop_sleep(NR_LOOPS);
	time2 = caa_get_cycles();
	printf("CPU clock cycles per loop: %g\n", (time2 - time1) /
						  (double)NR_LOOPS);
	return 0;
}
