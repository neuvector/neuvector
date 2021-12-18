/*
 * test_urcu_multiflavor.h
 *
 * Userspace RCU library - test multiple RCU flavors into one program
 *
 * Copyright February 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright February 2012 - Lai Jiangshan <laijs@cn.fujitsu.com>
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

extern int test_mf_memb(void);
extern int test_mf_mb(void);
extern int test_mf_signal(void);
extern int test_mf_qsbr(void);
extern int test_mf_bp(void);

