#ifndef _URCU_TLS_COMPAT_H
#define _URCU_TLS_COMPAT_H

/*
 * urcu/tls-compat.h
 *
 * Userspace RCU library - Thread-Local Storage Compatibility Header
 *
 * Copyright 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdlib.h>
#include <urcu/config.h>
#include <urcu/compiler.h>
#include <urcu/arch.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_RCU_TLS	/* Based on ax_tls.m4 */

/*
 * Hint: How to define/declare TLS variables of compound types
 *       such as array or function pointers?
 *
 * Answer: Use typedef to assign a type_name to the compound type.
 * Example: Define a TLS variable which is an int array with len=4:
 *
 * 	typedef int my_int_array_type[4];
 * 	DEFINE_URCU_TLS(my_int_array_type, var_name);
 *
 * Another example:
 * 	typedef void (*call_rcu_flavor)(struct rcu_head *, XXXX);
 * 	DECLARE_URCU_TLS(call_rcu_flavor, p_call_rcu);
 *
 * NOTE: URCU_TLS() is NOT async-signal-safe, you can't use it
 * inside any function which can be called from signal handler.
 *
 * But if pthread_getspecific() is async-signal-safe in your
 * platform, you can make URCU_TLS() async-signal-safe via:
 * ensuring the first call to URCU_TLS() of a given TLS variable of
 * all threads is called earliest from a non-signal handler function.
 *
 * Example: In any thread, the first call of URCU_TLS(rcu_reader)
 * is called from rcu_register_thread(), so we can ensure all later
 * URCU_TLS(rcu_reader) in any thread is async-signal-safe.
 *
 * Moreover, URCU_TLS variables should not be touched from signal
 * handlers setup with with sigaltstack(2).
 */

# define DECLARE_URCU_TLS(type, name)	\
	CONFIG_RCU_TLS type name

# define DEFINE_URCU_TLS(type, name)	\
	CONFIG_RCU_TLS type name

# define __DEFINE_URCU_TLS_GLOBAL(type, name)	\
	CONFIG_RCU_TLS type name

# define URCU_TLS(name)		(name)

#else /* #ifndef CONFIG_RCU_TLS */

/*
 * The *_1() macros ensure macro parameters are expanded.
 *
 * __DEFINE_URCU_TLS_GLOBAL and __URCU_TLS_CALL exist for the sole
 * purpose of notifying applications compiled against non-fixed 0.7 and
 * 0.8 userspace RCU headers and using multiple flavors concurrently to
 * recompile against fixed userspace RCU headers.
 */

# include <pthread.h>

struct urcu_tls {
	pthread_key_t key;
	pthread_mutex_t init_mutex;
	int init_done;
};

# define DECLARE_URCU_TLS_1(type, name)				\
	type *__tls_access2_ ## name(void)

# define DECLARE_URCU_TLS(type, name)				\
	DECLARE_URCU_TLS_1(type, name)

/*
 * Note: we don't free memory at process exit, since it will be dealt
 * with by the OS.
 */
# define __URCU_TLS_CALL_1(name)				\
	__tls_access2_ ## name

# define __URCU_TLS_CALL(name)					\
	__URCU_TLS_CALL_1(name)

# define DEFINE_URCU_TLS_1(type, name)				\
	type *__tls_access2_ ## name(void)			\
	{							\
		static struct urcu_tls __tls_ ## name = {	\
			.init_mutex = PTHREAD_MUTEX_INITIALIZER,\
			.init_done = 0,				\
		};						\
		void *__tls_p;					\
		if (!__tls_ ## name.init_done) {		\
			/* Mutex to protect concurrent init */	\
			pthread_mutex_lock(&__tls_ ## name.init_mutex); \
			if (!__tls_ ## name.init_done) {	\
				(void) pthread_key_create(&__tls_ ## name.key, \
					free);			\
				cmm_smp_wmb();	/* create key before write init_done */ \
				__tls_ ## name.init_done = 1;	\
			}					\
			pthread_mutex_unlock(&__tls_ ## name.init_mutex); \
		}						\
		cmm_smp_rmb();	/* read init_done before getting key */ \
		__tls_p = pthread_getspecific(__tls_ ## name.key); \
		if (caa_unlikely(__tls_p == NULL)) {		\
			__tls_p = calloc(1, sizeof(type));	\
			(void) pthread_setspecific(__tls_ ## name.key,	\
				__tls_p);			\
		}						\
		return __tls_p;					\
	}

/*
 * Define with and without macro expansion to handle erroneous callers.
 * Trigger an abort() if the caller application uses the clashing symbol
 * if a weak symbol is overridden.
 */
# define __DEFINE_URCU_TLS_GLOBAL(type, name)			\
	DEFINE_URCU_TLS_1(type, name)				\
	int __urcu_tls_symbol_refcount_ ## name __attribute__((weak)); \
	static __attribute__((constructor))			\
	void __urcu_tls_inc_refcount_ ## name(void)		\
	{							\
		__urcu_tls_symbol_refcount_ ## name++;		\
	}							\
	type *__tls_access_ ## name(void)			\
	{							\
		if (__urcu_tls_symbol_refcount_ ## name > 1) {	\
			fprintf(stderr, "Error: Userspace RCU symbol clash for multiple concurrent flavors. Please upgrade liburcu libraries and headers, then recompile your application.\n"); \
			abort();				\
		} 						\
		return __URCU_TLS_CALL(name)();			\
	}

# define DEFINE_URCU_TLS(type, name)				\
	DEFINE_URCU_TLS_1(type, name)

# define URCU_TLS_1(name)	(*__tls_access2_ ## name())

# define URCU_TLS(name)		URCU_TLS_1(name)

#endif	/* #else #ifndef CONFIG_RCU_TLS */

#ifdef __cplusplus
}
#endif

#endif /* _URCU_TLS_COMPAT_H */
