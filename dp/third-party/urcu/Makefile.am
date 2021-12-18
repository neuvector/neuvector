ACLOCAL_AMFLAGS=-I config

AM_CPPFLAGS = -I$(top_builddir)/urcu

#Add the -version-info directly here since we are only building
# library that use the version-info
AM_LDFLAGS=-lpthread -version-info $(URCU_LIBRARY_VERSION)
AM_CFLAGS=-Wall

SUBDIRS = . doc tests

include_HEADERS = urcu.h urcu-bp.h urcu-call-rcu.h urcu-defer.h \
		urcu-pointer.h urcu-qsbr.h urcu-flavor.h
nobase_dist_include_HEADERS = urcu/compiler.h urcu/hlist.h urcu/list.h \
		urcu/rculist.h urcu/rcuhlist.h urcu/system.h urcu/futex.h \
		urcu/uatomic/generic.h urcu/arch/generic.h urcu/wfstack.h \
		urcu/wfqueue.h urcu/rculfstack.h urcu/rculfqueue.h \
		urcu/ref.h urcu/cds.h urcu/urcu_ref.h urcu/urcu-futex.h \
		urcu/uatomic_arch.h urcu/rculfhash.h urcu/wfcqueue.h \
		urcu/lfstack.h \
		$(top_srcdir)/urcu/map/*.h \
		$(top_srcdir)/urcu/static/*.h \
		urcu/tls-compat.h
nobase_nodist_include_HEADERS = urcu/arch.h urcu/uatomic.h urcu/config.h

dist_noinst_HEADERS = urcu-die.h urcu-wait.h

EXTRA_DIST = $(top_srcdir)/urcu/arch/*.h $(top_srcdir)/urcu/uatomic/*.h \
		gpl-2.0.txt lgpl-2.1.txt lgpl-relicensing.txt \
		LICENSE compat_arch_x86.c \
		urcu-call-rcu-impl.h urcu-defer-impl.h \
		rculfhash-internal.h

if COMPAT_ARCH
COMPAT=compat_arch_@ARCHTYPE@.c
else
COMPAT=
endif

COMPAT+=compat_futex.c

RCULFHASH = rculfhash.c rculfhash-mm-order.c rculfhash-mm-chunk.c \
		rculfhash-mm-mmap.c

lib_LTLIBRARIES = liburcu-common.la \
		liburcu.la liburcu-qsbr.la \
		liburcu-mb.la liburcu-signal.la liburcu-bp.la \
		liburcu-cds.la

#
# liburcu-common contains wait-free queues (needed by call_rcu) as well
# as futex fallbacks.
#
liburcu_common_la_SOURCES = wfqueue.c wfcqueue.c wfstack.c $(COMPAT)

liburcu_la_SOURCES = urcu.c urcu-pointer.c $(COMPAT)
liburcu_la_LIBADD = liburcu-common.la

liburcu_qsbr_la_SOURCES = urcu-qsbr.c urcu-pointer.c $(COMPAT)
liburcu_qsbr_la_LIBADD = liburcu-common.la

liburcu_mb_la_SOURCES = urcu.c urcu-pointer.c $(COMPAT)
liburcu_mb_la_CFLAGS = -DRCU_MB
liburcu_mb_la_LIBADD = liburcu-common.la

liburcu_signal_la_SOURCES = urcu.c urcu-pointer.c $(COMPAT)
liburcu_signal_la_CFLAGS = -DRCU_SIGNAL
liburcu_signal_la_LIBADD = liburcu-common.la

liburcu_bp_la_SOURCES = urcu-bp.c urcu-pointer.c $(COMPAT)
liburcu_bp_la_LIBADD = liburcu-common.la

liburcu_cds_la_SOURCES = rculfqueue.c rculfstack.c lfstack.c \
	$(RCULFHASH) $(COMPAT)
liburcu_cds_la_LIBADD = liburcu-common.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liburcu-cds.pc liburcu.pc liburcu-bp.pc liburcu-qsbr.pc \
	liburcu-signal.pc liburcu-mb.pc

dist_doc_DATA = README ChangeLog

dist_noinst_DATA = CodingStyle

.PHONY: bench regtest
bench:
	cd tests && $(MAKE) $(AM_MAKEFLAGS) bench
regtest:
	cd tests && $(MAKE) $(AM_MAKEFLAGS) regtest
