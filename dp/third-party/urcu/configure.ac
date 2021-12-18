#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_INIT([userspace-rcu],[0.8.9],[mathieu dot desnoyers at efficios dot com])

# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST([URCU_LIBRARY_VERSION], [2:0:0])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

m4_include([config/ax_tls.m4])

AC_CONFIG_SRCDIR([urcu.h])

AC_CONFIG_HEADERS([config.h urcu/config.h])

AH_TEMPLATE([CONFIG_RCU_SMP], [Enable SMP support. With SMP support enabled, uniprocessors are also supported. With SMP support disabled, UP systems work fine, but the behavior of SMP systems is undefined.])
AH_TEMPLATE([CONFIG_RCU_HAVE_FENCE], [Defined when on a system that has memory fence instructions.])
AH_TEMPLATE([CONFIG_RCU_HAVE_FUTEX], [Defined when on a system with futex support.])
AH_TEMPLATE([CONFIG_RCU_COMPAT_ARCH], [Compatibility mode for i386 which lacks cmpxchg instruction.])
AH_TEMPLATE([CONFIG_RCU_ARM_HAVE_DMB], [Use the dmb instruction if available for use on ARM.])
AH_TEMPLATE([CONFIG_RCU_TLS], [TLS provided by the compiler.])

# Allow overriding storage used for TLS variables.
AC_ARG_ENABLE([compiler-tls],
	AS_HELP_STRING([--disable-compiler-tls], [Use pthread_getspecific() to emulate Thread Local Storage (TLS) variables.]),
	[def_compiler_tls=$enableval],
	[def_compiler_tls="yes"])

# If not overridden, use ax_tls.m4 to check if TLS is available.
AS_IF([test "x$def_compiler_tls" = "xyes"],
	[AX_TLS([def_tls_detect=$ac_cv_tls], [:])],
	[:])

AS_IF([test "x$def_tls_detect" = "x"],
	[:],
	[AC_DEFINE_UNQUOTED([CONFIG_RCU_TLS], $def_tls_detect)])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
LT_INIT

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero gettimeofday munmap sched_getcpu strtoul sysconf])

# Find arch type
AS_CASE([$host_cpu],
	[i386], [ARCHTYPE="x86" && SUBARCHTYPE="x86compat"],
	[i486], [ARCHTYPE="x86"],
	[i586], [ARCHTYPE="x86"],
	[i686], [ARCHTYPE="x86"],
	[amd64], [ARCHTYPE="x86"],
	[x86_64], [ARCHTYPE="x86"],
	[powerpc], [ARCHTYPE="ppc"],
	[ppc64], [ARCHTYPE="ppc"],
	[powerpc64], [ARCHTYPE="ppc"],
	[powerpc64le], [ARCHTYPE="gcc"],
	[ppc], [ARCHTYPE="ppc"],
	[s390], [ARCHTYPE="s390"],
	[s390x], [ARCHTYPE="s390"],
	[sparc], [ARCHTYPE="sparc64"],
	[sparc64], [ARCHTYPE="sparc64"],
	[alpha*], [ARCHTYPE="alpha"],
	[ia64], [ARCHTYPE="gcc"],
	[arm*], [ARCHTYPE="arm"],
	[aarch64], [ARCHTYPE="gcc"],
	[mips*], [ARCHTYPE="mips"],
	[tile*], [ARCHTYPE="gcc"],
	[ARCHTYPE="unknown"]
)

AC_SUBST(ARCHTYPE)
AC_SUBST(SUBARCHTYPE)

UATOMICSRC=urcu/uatomic/$ARCHTYPE.h
ARCHSRC=urcu/arch/$ARCHTYPE.h

AS_IF([test "x$SUBARCHTYPE" = xx86compat],[
	AC_DEFINE([CONFIG_RCU_COMPAT_ARCH], [1])
])

AS_IF([test "$host_cpu" = "armv7l"],[
	CFLAGS="$CFLAGS -mcpu=cortex-a9 -mtune=cortex-a9 -O1"
])

# ARM-specific checks
AS_IF([test "x$ARCHTYPE" = "xarm"],[
	AC_MSG_CHECKING([for dmb instruction])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
				int main()
				{
					asm volatile("dmb":::"memory");
					return 0;
				}
		]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE([CONFIG_RCU_ARM_HAVE_DMB], [1])
	],[
		AC_MSG_RESULT([no])
	])
])

# Tile-specific checks
AS_IF([echo "$host_cpu" | grep "^tile"],[
	AC_MSG_CHECKING([for Tile architecture type])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
				#ifndef __tilegx__
				#error
				#endif
		]])
	],[
		AC_MSG_RESULT([ok])
	],[
		AC_MSG_FAILURE([URCU has only been tested on the TileGx architecture. For other Tile* architectures, please run the tests first and report the results to the maintainer so that proper support can be added.])
	])
])

# x86-specific checks
AS_IF([test "x$ARCHTYPE" = "xx86"],[
	AC_MSG_CHECKING([if architecture really supports the mfence instruction])
	#For now, using lock; addl compatibility mode even for i686, because the
	#Pentium III is seen as a i686, but lacks mfence instruction.
	#Only using fence for x86_64.
	AS_IF([test "x$host_cpu" != "xi386" -a "x$host_cpu" != "xi486" -a "x$host_cpu" != "xi586" -a "x$host_cpu" != "xi686"],[
		AC_MSG_RESULT([yes])
		AC_DEFINE([CONFIG_RCU_HAVE_FENCE], [1])
	],[
		AC_MSG_RESULT([no])
	])
])

# Check if sys_futex() is available
AC_MSG_CHECKING([for sys_futex()])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
		#include <sys/syscall.h>
		#ifndef __NR_futex
		#error "futexes not available"
		#endif
	]])
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE([CONFIG_RCU_HAVE_FUTEX], [1])
	compat_futex_test=0
],[
	AC_MSG_RESULT([no])
	compat_futex_test=1
])

AM_CONDITIONAL([COMPAT_FUTEX], [test "x$compat_futex_test" = "x1"])
AM_CONDITIONAL([COMPAT_ARCH], [test "x$SUBARCHTYPE" = "xx86compat"])
AM_CONDITIONAL([NO_SHARED], [test "x$enable_shared" = "xno"])

# smp-support configure option
AC_ARG_ENABLE([smp-support], 
	AS_HELP_STRING([--disable-smp-support], [Disable SMP support. Warning: only use this on uniprocessor systems. [default=enabled]]),
	[def_smp_support=$enableval],
	[def_smp_support="yes"])
AS_IF([test "x$def_smp_support" = "xyes"], [AC_DEFINE([CONFIG_RCU_SMP], [1])])


# From the sched_setaffinity(2)'s man page:
# ~~~~
# The CPU affinity system calls were introduced in Linux kernel 2.5.8.
# The library interfaces were introduced in glibc 2.3.  Initially, the
# glibc interfaces included a cpusetsize argument.  In glibc 2.3.3,
# the cpuset size argument was removed, but this argument was
# restored in glibc 2.3.4.
# ~~~~

# In addition to that, some vendors ported the system call to 2.4
# kernels.

# Furthermore, when the function first appeared, the MASK argument was
# an unsigned long pointer, while later it was made into a cpu_set_t
# pointer.  Systems that have the cpu_set_t version also should have
# the CPU_ZERO, CPU_SET, etc. macros.

# All this mess means we have to cater for at least 3 different
# sched_setaffinity prototypes:

# ~~~~
#  int sched_setaffinity (pid_t pid, unsigned int len, unsigned long *mask);
#  int sched_setaffinity (pid_t __pid, size_t __cpusetsize, const cpu_set_t *__cpuset);
#  int sched_setaffinity (pid_t __pid, const cpu_set_t *__mask);
# ~~~~

# Since we define _GNU_SOURCE in the sources, must do so too in the
# autoconf tests, as defining _GNU_SOURCE or not exposes
# sched_setaffinity bits differently.
saved_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -D_GNU_SOURCE"

AC_CHECK_TYPES([cpu_set_t],
	[have_cpu_set_t="yes"],
	[have_cpu_set_t="no"],
	[#include <sched.h>])

# Confirm that we have CPU_ZERO, and it actually works.
AC_MSG_CHECKING([whether CPU_ZERO works])
AH_TEMPLATE([HAVE_CPU_ZERO], [Defined to 1 if we have CPU_ZERO and it works])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
		#define _GNU_SOURCE
		#include <sched.h>
		int main()
		{
			cpu_set_t foo; CPU_ZERO(&foo);
			return 0;
		}
	]])
],[
	AC_DEFINE(HAVE_CPU_ZERO, 1)
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# Confirm that we have CPU_SET, and it actually works.
AC_MSG_CHECKING([whether CPU_SET works])
AH_TEMPLATE([HAVE_CPU_SET], [Defined to 1 if we have CPU_SET and it works])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
		#define _GNU_SOURCE
		#include <sched.h>
		int main()
		{
			cpu_set_t foo, mask; CPU_SET(0, &foo);
			return 0;
		}
	]])
],[
	AC_DEFINE(HAVE_CPU_SET, 1)
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# First check if the function is available at all.
AC_CHECK_FUNCS([sched_setaffinity],[
	# Okay, we have it.  Check if also have cpu_set_t.  If we don't,
	# then we have the first version using unsigned long, and no
	# CPU_ZERO, etc. macros.  If we do have cpu_set_t, we may have the
	# version with 2 or 3 arguments.  In that case, CPU_ZERO, etc.,
	# should also be present, but we confirm nonetheless.

	AS_IF([test "x$have_cpu_set_t" = "xyes"], [
		# We do have it.
		# Check how many arguments does sched_setaffinity take.
		# Should be 3 or 2.
		AC_MSG_CHECKING([how many arguments sched_setaffinity takes])
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
				#include <sched.h>
				int main()
				{
					cpu_set_t foo;
					sched_setaffinity(0, sizeof (foo), &foo);
					return 0;
				}
			]])
		],
		[sched_set_affinity_args=3],
		[sched_set_affinity_args=2])
		AC_DEFINE_UNQUOTED(SCHED_SETAFFINITY_ARGS,
			$sched_set_affinity_args,
			[Defined to sched_setaffinity's number of arguments.])
		AC_MSG_RESULT([$sched_set_affinity_args])
	],[
		# No cpu_set_t, always 3 args.
		AC_DEFINE(SCHED_SETAFFINITY_ARGS, 3)
	])
])

CFLAGS=$saved_CFLAGS

AC_CONFIG_LINKS([
	urcu/arch.h:$ARCHSRC
	urcu/uatomic.h:$UATOMICSRC
])
AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/examples/Makefile
	tests/Makefile
	tests/common/Makefile
	tests/unit/Makefile
	tests/benchmark/Makefile
	tests/regression/Makefile
	liburcu.pc
	liburcu-bp.pc
	liburcu-cds.pc
	liburcu-qsbr.pc
	liburcu-mb.pc
	liburcu-signal.pc
])
AC_OUTPUT

# Report on selected configure options
AS_IF([test "x$def_smp_support" = "xyes"],[
	AS_ECHO("SMP support enabled.")
],[
	AS_ECHO("SMP support disabled.")
])

AS_IF([test "x$def_tls_detect" = "x"],[
	AS_ECHO("Thread Local Storage (TLS): pthread_getspecific().")
],[
	AS_ECHO("Thread Local Storage (TLS): $def_tls_detect.")
])
