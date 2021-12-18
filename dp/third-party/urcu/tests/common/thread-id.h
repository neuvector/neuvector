#ifndef _TEST_THREAD_ID_H
#define _TEST_THREAD_ID_H

/*
 * thread-id.h
 *
 * Userspace RCU library - thread ID
 *
 * Copyright 2013 - Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#ifdef __linux__
# include <syscall.h>

# if defined(_syscall0)
_syscall0(pid_t, gettid)
# elif defined(__NR_gettid)
static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
# endif

static inline
unsigned long urcu_get_thread_id(void)
{
	return (unsigned long) gettid();
}
#elif defined(__FreeBSD__)
# include <pthread_np.h>

static inline
unsigned long urcu_get_thread_id(void)
{
	return (unsigned long) pthread_getthreadid_np();
}
#else
# warning "use pid as thread ID"
static inline
unsigned long urcu_get_thread_id(void)
{
	return (unsigned long) getpid();
}
#endif

#endif /* _TEST_THREAD_ID_H */
