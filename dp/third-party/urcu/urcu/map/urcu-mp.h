#ifndef _URCU_MAP_H
#define _URCU_MAP_H

/*
 * urcu/map/urcu-mp.h
 *
 * Userspace RCU header -- name mapping to allow multiple flavors to be
 * used in the same executable.
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 *
 * LGPL-compatible code should include this header with :
 *
 * #define _LGPL_SOURCE
 * #include <urcu.h>
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
 *
 * IBM's contributions to this file may be relicensed under LGPLv2 or later.
 */

/* Mapping macros to allow multiple flavors in a single binary. */

#define rcu_read_lock			rcu_read_lock_mp
#define _rcu_read_lock			_rcu_read_lock_mp
#define rcu_read_unlock			rcu_read_unlock_mp
#define _rcu_read_unlock		_rcu_read_unlock_mp
#define rcu_read_ongoing		rcu_read_ongoing_mp
#define _rcu_read_ongoing		_rcu_read_ongoing_mp
#define rcu_register_thread		rcu_register_thread_mp
#define rcu_unregister_thread		rcu_unregister_thread_mp
#define rcu_init			rcu_init_mp
#define synchronize_rcu			synchronize_rcu_mp
#define rcu_reader			rcu_reader_mp
#define rcu_gp				rcu_gp_mp

#define rcu_quiescent_state		rcu_quiescent_state_mp
#define rcu_thread_offline		rcu_thread_offline_mp
#define rcu_thread_online		rcu_thread_online_mp
#define rcu_read_lock_online		rcu_read_lock_online_mp
#define rcu_read_unlock_online		rcu_read_unlock_online_mp

#define get_cpu_call_rcu_data		get_cpu_call_rcu_data_mp
#define get_call_rcu_thread		get_call_rcu_thread_mp
#define create_call_rcu_data		create_call_rcu_data_mp
#define set_cpu_call_rcu_data		set_cpu_call_rcu_data_mp
#define get_default_call_rcu_data	get_default_call_rcu_data_mp
#define get_call_rcu_data		get_call_rcu_data_mp
#define get_thread_call_rcu_data	get_thread_call_rcu_data_mp
#define set_thread_call_rcu_data	set_thread_call_rcu_data_mp
#define create_all_cpu_call_rcu_data	create_all_cpu_call_rcu_data_mp
#define free_all_cpu_call_rcu_data	free_all_cpu_call_rcu_data_mp
#define call_rcu			call_rcu_mp
#define call_rcu_data_free		call_rcu_data_free_mp
#define call_rcu_before_fork		call_rcu_before_fork_mp
#define call_rcu_after_fork_parent	call_rcu_after_fork_parent_mp
#define call_rcu_after_fork_child	call_rcu_after_fork_child_mp
#define rcu_barrier			rcu_barrier_mp

#define defer_rcu			defer_rcu_mp
#define rcu_defer_register_thread	rcu_defer_register_thread_mp
#define rcu_defer_unregister_thread	rcu_defer_unregister_thread_mp
#define rcu_defer_barrier		rcu_defer_barrier_mp
#define rcu_defer_barrier_thread	rcu_defer_barrier_thread_mp
#define rcu_defer_exit			rcu_defer_exit_mp

#define rcu_flavor			rcu_flavor_mp

/* Specific to mpARRIER flavor */
#define rcu_has_sys_mparrier		rcu_has_sys_mparrier_mp

#endif /* _URCU_MAP_H */
