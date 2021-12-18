#ifndef _URCU_UATOMIC_GENERIC_H
#define _URCU_UATOMIC_GENERIC_H

/*
 * Copyright (c) 1991-1994 by Xerox Corporation.  All rights reserved.
 * Copyright (c) 1996-1999 by Silicon Graphics.  All rights reserved.
 * Copyright (c) 1999-2004 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2009      Mathieu Desnoyers
 * Copyright (c) 2010      Paolo Bonzini
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 *
 * Code inspired from libuatomic_ops-1.2, inherited in part from the
 * Boehm-Demers-Weiser conservative garbage collector.
 */

#include <stdint.h>
#include <urcu/compiler.h>
#include <urcu/system.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef uatomic_set
#define uatomic_set(addr, v)	((void) CMM_STORE_SHARED(*(addr), (v)))
#endif

#ifndef uatomic_read
#define uatomic_read(addr)	CMM_LOAD_SHARED(*(addr))
#endif

#if !defined __OPTIMIZE__  || defined UATOMIC_NO_LINK_ERROR
static inline __attribute__((always_inline))
void _uatomic_link_error(void)
{
#ifdef ILLEGAL_INSTR
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__(ILLEGAL_INSTR);
#else
	__builtin_trap();
#endif
}

#else /* #if !defined __OPTIMIZE__  || defined UATOMIC_NO_LINK_ERROR */
extern void _uatomic_link_error(void);
#endif /* #else #if !defined __OPTIMIZE__  || defined UATOMIC_NO_LINK_ERROR */

/* cmpxchg */

#ifndef uatomic_cmpxchg
static inline __attribute__((always_inline))
unsigned long _uatomic_cmpxchg(void *addr, unsigned long old,
			      unsigned long _new, int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
		return __sync_val_compare_and_swap_1((uint8_t *) addr, old,
				_new);
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
		return __sync_val_compare_and_swap_2((uint16_t *) addr, old,
				_new);
#endif
	case 4:
		return __sync_val_compare_and_swap_4((uint32_t *) addr, old,
				_new);
#if (CAA_BITS_PER_LONG == 64)
	case 8:
		return __sync_val_compare_and_swap_8((uint64_t *) addr, old,
				_new);
#endif
	}
	_uatomic_link_error();
	return 0;
}


#define uatomic_cmpxchg(addr, old, _new)				      \
	((__typeof__(*(addr))) _uatomic_cmpxchg((addr),			      \
						caa_cast_long_keep_sign(old), \
						caa_cast_long_keep_sign(_new),\
						sizeof(*(addr))))


/* uatomic_and */

#ifndef uatomic_and
static inline __attribute__((always_inline))
void _uatomic_and(void *addr, unsigned long val,
		  int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
		__sync_and_and_fetch_1((uint8_t *) addr, val);
		return;
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
		__sync_and_and_fetch_2((uint16_t *) addr, val);
		return;
#endif
	case 4:
		__sync_and_and_fetch_4((uint32_t *) addr, val);
		return;
#if (CAA_BITS_PER_LONG == 64)
	case 8:
		__sync_and_and_fetch_8((uint64_t *) addr, val);
		return;
#endif
	}
	_uatomic_link_error();
}

#define uatomic_and(addr, v)			\
	(_uatomic_and((addr),			\
		caa_cast_long_keep_sign(v),	\
		sizeof(*(addr))))
#define cmm_smp_mb__before_uatomic_and()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_and()		cmm_barrier()

#endif

/* uatomic_or */

#ifndef uatomic_or
static inline __attribute__((always_inline))
void _uatomic_or(void *addr, unsigned long val,
		 int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
		__sync_or_and_fetch_1((uint8_t *) addr, val);
		return;
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
		__sync_or_and_fetch_2((uint16_t *) addr, val);
		return;
#endif
	case 4:
		__sync_or_and_fetch_4((uint32_t *) addr, val);
		return;
#if (CAA_BITS_PER_LONG == 64)
	case 8:
		__sync_or_and_fetch_8((uint64_t *) addr, val);
		return;
#endif
	}
	_uatomic_link_error();
	return;
}

#define uatomic_or(addr, v)			\
	(_uatomic_or((addr),			\
		caa_cast_long_keep_sign(v),	\
		sizeof(*(addr))))
#define cmm_smp_mb__before_uatomic_or()		cmm_barrier()
#define cmm_smp_mb__after_uatomic_or()		cmm_barrier()

#endif


/* uatomic_add_return */

#ifndef uatomic_add_return
static inline __attribute__((always_inline))
unsigned long _uatomic_add_return(void *addr, unsigned long val,
				 int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
		return __sync_add_and_fetch_1((uint8_t *) addr, val);
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
		return __sync_add_and_fetch_2((uint16_t *) addr, val);
#endif
	case 4:
		return __sync_add_and_fetch_4((uint32_t *) addr, val);
#if (CAA_BITS_PER_LONG == 64)
	case 8:
		return __sync_add_and_fetch_8((uint64_t *) addr, val);
#endif
	}
	_uatomic_link_error();
	return 0;
}


#define uatomic_add_return(addr, v)					    \
	((__typeof__(*(addr))) _uatomic_add_return((addr),		    \
						caa_cast_long_keep_sign(v), \
						sizeof(*(addr))))
#endif /* #ifndef uatomic_add_return */

#ifndef uatomic_xchg
/* xchg */

static inline __attribute__((always_inline))
unsigned long _uatomic_exchange(void *addr, unsigned long val, int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
	{
		uint8_t old;

		do {
			old = uatomic_read((uint8_t *) addr);
		} while (!__sync_bool_compare_and_swap_1((uint8_t *) addr,
				old, val));

		return old;
	}
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
	{
		uint16_t old;

		do {
			old = uatomic_read((uint16_t *) addr);
		} while (!__sync_bool_compare_and_swap_2((uint16_t *) addr,
				old, val));

		return old;
	}
#endif
	case 4:
	{
		uint32_t old;

		do {
			old = uatomic_read((uint32_t *) addr);
		} while (!__sync_bool_compare_and_swap_4((uint32_t *) addr,
				old, val));

		return old;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		uint64_t old;

		do {
			old = uatomic_read((uint64_t *) addr);
		} while (!__sync_bool_compare_and_swap_8((uint64_t *) addr,
				old, val));

		return old;
	}
#endif
	}
	_uatomic_link_error();
	return 0;
}

#define uatomic_xchg(addr, v)						    \
	((__typeof__(*(addr))) _uatomic_exchange((addr),		    \
						caa_cast_long_keep_sign(v), \
						sizeof(*(addr))))
#endif /* #ifndef uatomic_xchg */

#else /* #ifndef uatomic_cmpxchg */

#ifndef uatomic_and
/* uatomic_and */

static inline __attribute__((always_inline))
void _uatomic_and(void *addr, unsigned long val, int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
	{
		uint8_t old, oldt;

		oldt = uatomic_read((uint8_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old & val, 1);
		} while (oldt != old);

		return;
	}
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
	{
		uint16_t old, oldt;

		oldt = uatomic_read((uint16_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old & val, 2);
		} while (oldt != old);
	}
#endif
	case 4:
	{
		uint32_t old, oldt;

		oldt = uatomic_read((uint32_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old & val, 4);
		} while (oldt != old);

		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		uint64_t old, oldt;

		oldt = uatomic_read((uint64_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old & val, 8);
		} while (oldt != old);

		return;
	}
#endif
	}
	_uatomic_link_error();
}

#define uatomic_and(addr, v)			\
	(_uatomic_and((addr),			\
		caa_cast_long_keep_sign(v),	\
		sizeof(*(addr))))
#define cmm_smp_mb__before_uatomic_and()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_and()		cmm_barrier()

#endif /* #ifndef uatomic_and */

#ifndef uatomic_or
/* uatomic_or */

static inline __attribute__((always_inline))
void _uatomic_or(void *addr, unsigned long val, int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
	{
		uint8_t old, oldt;

		oldt = uatomic_read((uint8_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old | val, 1);
		} while (oldt != old);

		return;
	}
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
	{
		uint16_t old, oldt;

		oldt = uatomic_read((uint16_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old | val, 2);
		} while (oldt != old);

		return;
	}
#endif
	case 4:
	{
		uint32_t old, oldt;

		oldt = uatomic_read((uint32_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old | val, 4);
		} while (oldt != old);

		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		uint64_t old, oldt;

		oldt = uatomic_read((uint64_t *) addr);
		do {
			old = oldt;
			oldt = _uatomic_cmpxchg(addr, old, old | val, 8);
		} while (oldt != old);

		return;
	}
#endif
	}
	_uatomic_link_error();
}

#define uatomic_or(addr, v)			\
	(_uatomic_or((addr),			\
		caa_cast_long_keep_sign(v),	\
		sizeof(*(addr))))
#define cmm_smp_mb__before_uatomic_or()		cmm_barrier()
#define cmm_smp_mb__after_uatomic_or()		cmm_barrier()

#endif /* #ifndef uatomic_or */

#ifndef uatomic_add_return
/* uatomic_add_return */

static inline __attribute__((always_inline))
unsigned long _uatomic_add_return(void *addr, unsigned long val, int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
	{
		uint8_t old, oldt;

		oldt = uatomic_read((uint8_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint8_t *) addr,
                                               old, old + val);
		} while (oldt != old);

		return old + val;
	}
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
	{
		uint16_t old, oldt;

		oldt = uatomic_read((uint16_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint16_t *) addr,
                                               old, old + val);
		} while (oldt != old);

		return old + val;
	}
#endif
	case 4:
	{
		uint32_t old, oldt;

		oldt = uatomic_read((uint32_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint32_t *) addr,
                                               old, old + val);
		} while (oldt != old);

		return old + val;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		uint64_t old, oldt;

		oldt = uatomic_read((uint64_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint64_t *) addr,
                                               old, old + val);
		} while (oldt != old);

		return old + val;
	}
#endif
	}
	_uatomic_link_error();
	return 0;
}

#define uatomic_add_return(addr, v)					    \
	((__typeof__(*(addr))) _uatomic_add_return((addr),		    \
						caa_cast_long_keep_sign(v), \
						sizeof(*(addr))))
#endif /* #ifndef uatomic_add_return */

#ifndef uatomic_xchg
/* xchg */

static inline __attribute__((always_inline))
unsigned long _uatomic_exchange(void *addr, unsigned long val, int len)
{
	switch (len) {
#ifdef UATOMIC_HAS_ATOMIC_BYTE
	case 1:
	{
		uint8_t old, oldt;

		oldt = uatomic_read((uint8_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint8_t *) addr,
                                               old, val);
		} while (oldt != old);

		return old;
	}
#endif
#ifdef UATOMIC_HAS_ATOMIC_SHORT
	case 2:
	{
		uint16_t old, oldt;

		oldt = uatomic_read((uint16_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint16_t *) addr,
                                               old, val);
		} while (oldt != old);

		return old;
	}
#endif
	case 4:
	{
		uint32_t old, oldt;

		oldt = uatomic_read((uint32_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint32_t *) addr,
                                               old, val);
		} while (oldt != old);

		return old;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		uint64_t old, oldt;

		oldt = uatomic_read((uint64_t *) addr);
		do {
			old = oldt;
			oldt = uatomic_cmpxchg((uint64_t *) addr,
                                               old, val);
		} while (oldt != old);

		return old;
	}
#endif
	}
	_uatomic_link_error();
	return 0;
}

#define uatomic_xchg(addr, v)						    \
	((__typeof__(*(addr))) _uatomic_exchange((addr),		    \
						caa_cast_long_keep_sign(v), \
						sizeof(*(addr))))
#endif /* #ifndef uatomic_xchg */

#endif /* #else #ifndef uatomic_cmpxchg */

/* uatomic_sub_return, uatomic_add, uatomic_sub, uatomic_inc, uatomic_dec */

#ifndef uatomic_add
#define uatomic_add(addr, v)		(void)uatomic_add_return((addr), (v))
#define cmm_smp_mb__before_uatomic_add()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_add()		cmm_barrier()
#endif

#define uatomic_sub_return(addr, v)	\
	uatomic_add_return((addr), -(caa_cast_long_keep_sign(v)))
#define uatomic_sub(addr, v)		\
	uatomic_add((addr), -(caa_cast_long_keep_sign(v)))
#define cmm_smp_mb__before_uatomic_sub()	cmm_smp_mb__before_uatomic_add()
#define cmm_smp_mb__after_uatomic_sub()		cmm_smp_mb__after_uatomic_add()

#ifndef uatomic_inc
#define uatomic_inc(addr)		uatomic_add((addr), 1)
#define cmm_smp_mb__before_uatomic_inc()	cmm_smp_mb__before_uatomic_add()
#define cmm_smp_mb__after_uatomic_inc()		cmm_smp_mb__after_uatomic_add()
#endif

#ifndef uatomic_dec
#define uatomic_dec(addr)		uatomic_add((addr), -1)
#define cmm_smp_mb__before_uatomic_dec()	cmm_smp_mb__before_uatomic_add()
#define cmm_smp_mb__after_uatomic_dec()		cmm_smp_mb__after_uatomic_add()
#endif

#ifdef __cplusplus
}
#endif

#endif /* _URCU_UATOMIC_GENERIC_H */
