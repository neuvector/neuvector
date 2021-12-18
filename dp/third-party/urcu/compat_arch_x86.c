/*
 * compat_arch_x86.c
 *
 * Userspace RCU library - x86 compatibility checks
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
#include <urcu/uatomic.h>

/*
 * Using attribute "weak" for __rcu_cas_avail and
 * __urcu_x86_compat_mutex. Those are globally visible by the entire
 * program, even though many shared objects may have their own version.
 * The first version that gets loaded will be used by the entire
 * program (executable and all shared objects).
 */

/*
 * It does not really matter if the constructor is called before using
 * the library, as long as the caller checks if __rcu_cas_avail < 0 and calls
 * compat_arch_init() explicitely if needed.
 */
int __attribute__((constructor)) __rcu_cas_init(void);

/*
 * -1: unknown
 *  1: available
 *  0: unavailable
 */
__attribute__((weak))
int __rcu_cas_avail = -1;

__attribute__((weak))
pthread_mutex_t __urcu_x86_compat_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * get_eflags/set_eflags/compare_and_swap_is_available imported from glibc
 * 2.3.5. linuxthreads/sysdeps/i386/pt-machine.h.
 */

static int get_eflags (void)
{
	int res;
	__asm__ __volatile__ ("pushfl; popl %0" : "=r" (res) : );
	return res;
}

static void set_eflags (int newflags)
{
	__asm__ __volatile__ ("pushl %0; popfl" : : "r" (newflags) : "cc");
}

static int compare_and_swap_is_available (void)
{
	int oldflags = get_eflags ();
	int changed;
	/* Flip AC bit in EFLAGS.  */
	set_eflags (oldflags ^ 0x40000);
	/* See if bit changed.  */
	changed = (get_eflags () ^ oldflags) & 0x40000;
	/* Restore EFLAGS.  */
	set_eflags (oldflags);
	/* If the AC flag did not change, it's a 386 and it lacks cmpxchg.
	Otherwise, it's a 486 or above and it has cmpxchg.  */
	return changed != 0;
}

static void mutex_lock_signal_save(pthread_mutex_t *mutex, sigset_t *oldmask)
{
	sigset_t newmask;
	int ret;

	/* Disable signals */
	ret = sigfillset(&newmask);
	assert(!ret);
	ret = pthread_sigmask(SIG_BLOCK, &newmask, oldmask);
	assert(!ret);
	ret = pthread_mutex_lock(&__urcu_x86_compat_mutex);
	assert(!ret);
}

static void mutex_lock_signal_restore(pthread_mutex_t *mutex, sigset_t *oldmask)
{
	int ret;

	ret = pthread_mutex_unlock(&__urcu_x86_compat_mutex);
	assert(!ret);
	ret = pthread_sigmask(SIG_SETMASK, oldmask, NULL);
	assert(!ret);
}

unsigned long _compat_uatomic_set(void *addr, unsigned long _new, int len)
{
	sigset_t mask;
	unsigned long result;

	mutex_lock_signal_save(&__urcu_x86_compat_mutex, &mask);
	switch (len) {
	case 1:
		*(unsigned char *)addr = (unsigned char)_new;
		result = *(unsigned char *)addr;
		break;
	case 2:
		*(unsigned short *)addr = (unsigned short)_new;
		result = *(unsigned short *)addr;
		break;
	case 4:
		*(unsigned int *)addr = (unsigned int)_new;
		result = *(unsigned int *)addr;
		break;
	default:
		/*
		 * generate an illegal instruction. Cannot catch this with
		 * linker tricks when optimizations are disabled.
		 */
		result = 0;
		__asm__ __volatile__("ud2");
	}
	mutex_lock_signal_restore(&__urcu_x86_compat_mutex, &mask);
	return result;
}

unsigned long _compat_uatomic_xchg(void *addr, unsigned long _new, int len)
{
	sigset_t mask;
	unsigned long retval;

	mutex_lock_signal_save(&__urcu_x86_compat_mutex, &mask);
	switch (len) {
	case 1:
		retval = *(unsigned char *)addr;
		*(unsigned char *)addr = (unsigned char)_new;
		break;
	case 2:
		retval = *(unsigned short *)addr;
		*(unsigned short *)addr = (unsigned short)_new;
		break;
	case 4:
		retval = *(unsigned int *)addr;
		*(unsigned int *)addr = (unsigned int)_new;
		break;
	default:
		/*
		 * generate an illegal instruction. Cannot catch this with
		 * linker tricks when optimizations are disabled.
		 */
		retval = 0;	/* silence gcc warnings */
		__asm__ __volatile__("ud2");
	}
	mutex_lock_signal_restore(&__urcu_x86_compat_mutex, &mask);
	return retval;
}

unsigned long _compat_uatomic_cmpxchg(void *addr, unsigned long old,
				      unsigned long _new, int len)
{
	unsigned long retval;
	sigset_t mask;

	mutex_lock_signal_save(&__urcu_x86_compat_mutex, &mask);
	switch (len) {
	case 1:
	{
		unsigned char result = *(unsigned char *)addr;
		if (result == (unsigned char)old)
			*(unsigned char *)addr = (unsigned char)_new;
		retval = result;
		break;
	}
	case 2:
	{
		unsigned short result = *(unsigned short *)addr;
		if (result == (unsigned short)old)
			*(unsigned short *)addr = (unsigned short)_new;
		retval = result;
		break;
	}
	case 4:
	{
		unsigned int result = *(unsigned int *)addr;
		if (result == (unsigned int)old)
			*(unsigned int *)addr = (unsigned int)_new;
		retval = result;
		break;
	}
	default:
		/*
		 * generate an illegal instruction. Cannot catch this with
		 * linker tricks when optimizations are disabled.
		 */
		retval = 0;	/* silence gcc warnings */
		__asm__ __volatile__("ud2");
	}
	mutex_lock_signal_restore(&__urcu_x86_compat_mutex, &mask);
	return retval;
}

void _compat_uatomic_or(void *addr, unsigned long v, int len)
{
	sigset_t mask;

	mutex_lock_signal_save(&__urcu_x86_compat_mutex, &mask);
	switch (len) {
	case 1:
		*(unsigned char *)addr |= (unsigned char)v;
		break;
	case 2:
		*(unsigned short *)addr |= (unsigned short)v;
		break;
	case 4:
		*(unsigned int *)addr |= (unsigned int)v;
		break;
	default:
		/*
		 * generate an illegal instruction. Cannot catch this with
		 * linker tricks when optimizations are disabled.
		 */
		__asm__ __volatile__("ud2");
	}
	mutex_lock_signal_restore(&__urcu_x86_compat_mutex, &mask);
}

void _compat_uatomic_and(void *addr, unsigned long v, int len)
{
	sigset_t mask;

	mutex_lock_signal_save(&__urcu_x86_compat_mutex, &mask);
	switch (len) {
	case 1:
		*(unsigned char *)addr &= (unsigned char)v;
		break;
	case 2:
		*(unsigned short *)addr &= (unsigned short)v;
		break;
	case 4:
		*(unsigned int *)addr &= (unsigned int)v;
		break;
	default:
		/*
		 * generate an illegal instruction. Cannot catch this with
		 * linker tricks when optimizations are disabled.
		 */
		__asm__ __volatile__("ud2");
	}
	mutex_lock_signal_restore(&__urcu_x86_compat_mutex, &mask);
}

unsigned long _compat_uatomic_add_return(void *addr, unsigned long v, int len)
{
	sigset_t mask;
	unsigned long result;

	mutex_lock_signal_save(&__urcu_x86_compat_mutex, &mask);
	switch (len) {
	case 1:
		*(unsigned char *)addr += (unsigned char)v;
		result = *(unsigned char *)addr;
		break;
	case 2:
		*(unsigned short *)addr += (unsigned short)v;
		result = *(unsigned short *)addr;
		break;
	case 4:
		*(unsigned int *)addr += (unsigned int)v;
		result = *(unsigned int *)addr;
		break;
	default:
		/*
		 * generate an illegal instruction. Cannot catch this with
		 * linker tricks when optimizations are disabled.
		 */
		result = 0;	/* silence gcc warnings */
		__asm__ __volatile__("ud2");
	}
	mutex_lock_signal_restore(&__urcu_x86_compat_mutex, &mask);
	return result;
}

int __rcu_cas_init(void)
{
	if (__rcu_cas_avail < 0)
		__rcu_cas_avail = compare_and_swap_is_available();
	return __rcu_cas_avail;
}
