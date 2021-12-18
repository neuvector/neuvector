#ifndef _URCU_FLAVOR_H
#define _URCU_FLAVOR_H

/*
 * urcu-flavor.h
 *
 * Userspace RCU header - rcu flavor declarations
 *
 * Copyright (c) 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
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

#ifdef __cplusplus
extern "C" {
#endif

struct rcu_flavor_struct {
	void (*read_lock)(void);
	void (*read_unlock)(void);
	int (*read_ongoing)(void);
	void (*read_quiescent_state)(void);
	void (*update_call_rcu)(struct rcu_head *head,
				void (*func)(struct rcu_head *head));
	void (*update_synchronize_rcu)(void);
	void (*update_defer_rcu)(void (*fct)(void *p), void *p);

	void (*thread_offline)(void);
	void (*thread_online)(void);
	void (*register_thread)(void);
	void (*unregister_thread)(void);

	void (*barrier)(void);
};

#define DEFINE_RCU_FLAVOR(x)				\
const struct rcu_flavor_struct x = {			\
	.read_lock		= rcu_read_lock,	\
	.read_unlock		= rcu_read_unlock,	\
	.read_ongoing		= rcu_read_ongoing,	\
	.read_quiescent_state	= rcu_quiescent_state,	\
	.update_call_rcu	= call_rcu,		\
	.update_synchronize_rcu	= synchronize_rcu,	\
	.update_defer_rcu	= defer_rcu,		\
	.thread_offline		= rcu_thread_offline,	\
	.thread_online		= rcu_thread_online,	\
	.register_thread	= rcu_register_thread,	\
	.unregister_thread	= rcu_unregister_thread,\
	.barrier		= rcu_barrier,		\
}

extern const struct rcu_flavor_struct rcu_flavor;

#ifdef __cplusplus
}
#endif

#endif /* _URCU_FLAVOR_H */
