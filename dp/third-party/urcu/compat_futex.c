/*
 * compat_futex.c
 *
 * Userspace RCU library - sys_futex compatibility code
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>

#include <urcu/arch.h>
#include <urcu/futex.h>
#include <urcu/system.h>

/*
 * Using attribute "weak" for __urcu_compat_futex_lock and
 * __urcu_compat_futex_cond. Those are globally visible by the entire
 * program, even though many shared objects may have their own version.
 * The first version that gets loaded will be used by the entire program
 * (executable and all shared objects).
 */

__attribute__((weak))
pthread_mutex_t __urcu_compat_futex_lock = PTHREAD_MUTEX_INITIALIZER;
__attribute__((weak))
pthread_cond_t __urcu_compat_futex_cond = PTHREAD_COND_INITIALIZER;

/*
 * _NOT SIGNAL-SAFE_. pthread_cond is not signal-safe anyway. Though.
 * For now, timeout, uaddr2 and val3 are unused.
 * Waiter will relinquish the CPU until woken up.
 */

int compat_futex_noasync(int32_t *uaddr, int op, int32_t val,
	const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	int ret = 0, lockret;

	/*
	 * Check if NULL. Don't let users expect that they are taken into
	 * account. 
	 */
	assert(!timeout);
	assert(!uaddr2);
	assert(!val3);

	/*
	 * memory barriers to serialize with the previous uaddr modification.
	 */
	cmm_smp_mb();

	lockret = pthread_mutex_lock(&__urcu_compat_futex_lock);
	if (lockret) {
		errno = lockret;
		ret = -1;
		goto end;
	}
	switch (op) {
	case FUTEX_WAIT:
		/*
		 * Wait until *uaddr is changed to something else than "val".
		 * Comparing *uaddr content against val figures out which
		 * thread has been awakened.
		 */
		while (CMM_LOAD_SHARED(*uaddr) == val)
			pthread_cond_wait(&__urcu_compat_futex_cond,
				&__urcu_compat_futex_lock);
		break;
	case FUTEX_WAKE:
		/*
		 * Each wake is sending a broadcast, thus attempting wakeup of
		 * all awaiting threads, independently of their respective
		 * uaddr.
		 */
		pthread_cond_broadcast(&__urcu_compat_futex_cond);
		break;
	default:
		errno = EINVAL;
		ret = -1;
	}
	lockret = pthread_mutex_unlock(&__urcu_compat_futex_lock);
	if (lockret) {
		errno = lockret;
		ret = -1;
	}
end:
	return ret;
}

/*
 * _ASYNC SIGNAL-SAFE_.
 * For now, timeout, uaddr2 and val3 are unused.
 * Waiter will busy-loop trying to read the condition.
 * It is OK to use compat_futex_async() on a futex address on which
 * futex() WAKE operations are also performed.
 */

int compat_futex_async(int32_t *uaddr, int op, int32_t val,
	const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	int ret = 0;

	/*
	 * Check if NULL. Don't let users expect that they are taken into
	 * account. 
	 */
	assert(!timeout);
	assert(!uaddr2);
	assert(!val3);

	/*
	 * Ensure previous memory operations on uaddr have completed.
	 */
	cmm_smp_mb();

	switch (op) {
	case FUTEX_WAIT:
		while (CMM_LOAD_SHARED(*uaddr) == val) {
			if (poll(NULL, 0, 10) < 0) {
				ret = -1;
				/* Keep poll errno. Caller handles EINTR. */
				goto end;
			}
		}
		break;
	case FUTEX_WAKE:
		break;
	default:
		errno = EINVAL;
		ret = -1;
	}
end:
	return ret;
}
