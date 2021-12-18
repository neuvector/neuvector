#ifndef _URCU_QSBR_MAP_H
#define _URCU_QSBR_MAP_H

/*
 * urcu-map.h
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

#define rcu_read_lock			rcu_read_lock_qsbr
#define _rcu_read_lock			_rcu_read_lock_qsbr
#define rcu_read_unlock			rcu_read_unlock_qsbr
#define _rcu_read_unlock		_rcu_read_unlock_qsbr
#define rcu_read_ongoing		rcu_read_ongoing_qsbr
#define _rcu_read_ongoing		_rcu_read_ongoing_qsbr
#define rcu_quiescent_state		rcu_quiescent_state_qsbr
#define _rcu_quiescent_state		_rcu_quiescent_state_qsbr
#define rcu_thread_offline		rcu_thread_offline_qsbr
#define rcu_thread_online		rcu_thread_online_qsbr
#define rcu_register_thread		rcu_register_thread_qsbr
#define rcu_unregister_thread		rcu_unregister_thread_qsbr
#define rcu_exit			rcu_exit_qsbr
#define synchronize_rcu			synchronize_rcu_qsbr
#define rcu_reader			rcu_reader_qsbr
#define rcu_gp				rcu_gp_qsbr

#define get_cpu_call_rcu_data		get_cpu_call_rcu_data_qsbr
#define get_call_rcu_thread		get_call_rcu_thread_qsbr
#define create_call_rcu_data		create_call_rcu_data_qsbr
#define set_cpu_call_rcu_data		set_cpu_call_rcu_data_qsbr
#define get_default_call_rcu_data	get_default_call_rcu_data_qsbr
#define get_call_rcu_data		get_call_rcu_data_qsbr
#define get_thread_call_rcu_data	get_thread_call_rcu_data_qsbr
#define set_thread_call_rcu_data	set_thread_call_rcu_data_qsbr
#define create_all_cpu_call_rcu_data	create_all_cpu_call_rcu_data_qsbr
#define call_rcu			call_rcu_qsbr
#define call_rcu_data_free		call_rcu_data_free_qsbr
#define call_rcu_before_fork		call_rcu_before_fork_qsbr
#define call_rcu_after_fork_parent	call_rcu_after_fork_parent_qsbr
#define call_rcu_after_fork_child	call_rcu_after_fork_child_qsbr
#define rcu_barrier			rcu_barrier_qsbr

#define defer_rcu			defer_rcu_qsbr
#define rcu_defer_register_thread	rcu_defer_register_thread_qsbr
#define rcu_defer_unregister_thread	rcu_defer_unregister_thread_qsbr
#define	rcu_defer_barrier		rcu_defer_barrier_qsbr
#define rcu_defer_barrier_thread	rcu_defer_barrier_thread_qsbr
#define rcu_defer_exit			rcu_defer_exit_qsbr

#define rcu_flavor			rcu_flavor_qsbr

#endif /* _URCU_QSBR_MAP_H */
