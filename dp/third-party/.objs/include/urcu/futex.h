#ifndef _URCU_FUTEX_H
#define _URCU_FUTEX_H

/*
 * urcu-futex.h
 *
 * Userspace RCU - sys_futex/compat_futex header.
 *
 * Copyright 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <urcu/config.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif 

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1

/*
 * sys_futex compatibility header.
 * Use *only* *either of* futex_noasync OR futex_async on a given address.
 *
 * futex_noasync cannot be executed in signal handlers, but ensures that
 * it will be put in a wait queue even in compatibility mode.
 *
 * futex_async is signal-handler safe for the wakeup. It uses polling
 * on the wait-side in compatibility mode.
 *
 * BEWARE: sys_futex() FUTEX_WAIT may return early if interrupted
 * (returns EINTR).
 */

extern int compat_futex_noasync(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3);
extern int compat_futex_async(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3);

#ifdef CONFIG_RCU_HAVE_FUTEX

#include <unistd.h>
#include <errno.h>
#include <urcu/compiler.h>
#include <syscall.h>

static inline int futex(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	return syscall(__NR_futex, uaddr, op, val, timeout,
			uaddr2, val3);
}

static inline int futex_noasync(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	int ret;

	ret = futex(uaddr, op, val, timeout, uaddr2, val3);
	if (caa_unlikely(ret < 0 && errno == ENOSYS)) {
		/*
		 * The fallback on ENOSYS is the async-safe version of
		 * the compat futex implementation, because the
		 * async-safe compat implementation allows being used
		 * concurrently with calls to futex(). Indeed, sys_futex
		 * FUTEX_WAIT, on some architectures (mips and parisc),
		 * within a given process, spuriously return ENOSYS due
		 * to signal restart bugs on some kernel versions.
		 */
		return compat_futex_async(uaddr, op, val, timeout,
				uaddr2, val3);
	}
	return ret;

}

static inline int futex_async(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	int ret;

	ret = futex(uaddr, op, val, timeout, uaddr2, val3);
	if (caa_unlikely(ret < 0 && errno == ENOSYS)) {
		return compat_futex_async(uaddr, op, val, timeout,
				uaddr2, val3);
	}
	return ret;
}

#else

static inline int futex_noasync(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	return compat_futex_noasync(uaddr, op, val, timeout, uaddr2, val3);
}

static inline int futex_async(int32_t *uaddr, int op, int32_t val,
		const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	return compat_futex_async(uaddr, op, val, timeout, uaddr2, val3);
}

#endif

#ifdef __cplusplus 
}
#endif

#endif /* _URCU_FUTEX_H */
