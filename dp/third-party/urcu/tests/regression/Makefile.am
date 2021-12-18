AM_LDFLAGS=-lpthread
AM_CFLAGS=-I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/tests/common -g

noinst_PROGRAMS = test_urcu_fork \
	rcutorture_urcu \
	rcutorture_urcu_signal \
	rcutorture_urcu_mb \
	rcutorture_urcu_bp \
	rcutorture_urcu_qsbr

noinst_HEADERS = rcutorture.h

URCU_COMMON_LIB=$(top_builddir)/liburcu-common.la
URCU_LIB=$(top_builddir)/liburcu.la
URCU_QSBR_LIB=$(top_builddir)/liburcu-qsbr.la
URCU_MB_LIB=$(top_builddir)/liburcu-mb.la
URCU_SIGNAL_LIB=$(top_builddir)/liburcu-signal.la
URCU_BP_LIB=$(top_builddir)/liburcu-bp.la
URCU_CDS_LIB=$(top_builddir)/liburcu-cds.la

test_urcu_fork_SOURCES = test_urcu_fork.c
test_urcu_fork_LDADD = $(URCU_LIB)

rcutorture_urcu_SOURCES = urcutorture.c
rcutorture_urcu_CFLAGS = -DRCU_MEMBARRIER $(AM_CFLAGS)
rcutorture_urcu_LDADD = $(URCU_LIB)

rcutorture_urcu_mb_SOURCES = urcutorture.c
rcutorture_urcu_mb_CFLAGS = -DRCU_MB $(AM_CFLAGS)
rcutorture_urcu_mb_LDADD = $(URCU_MB_LIB)

rcutorture_urcu_qsbr_SOURCES = urcutorture.c
rcutorture_urcu_qsbr_CFLAGS = -DTORTURE_QSBR -DRCU_QSBR $(AM_CFLAGS)
rcutorture_urcu_qsbr_LDADD = $(URCU_QSBR_LIB)

rcutorture_urcu_signal_SOURCES = urcutorture.c
rcutorture_urcu_signal_CFLAGS = -DRCU_SIGNAL $(AM_CFLAGS)
rcutorture_urcu_signal_LDADD = $(URCU_SIGNAL_LIB)

rcutorture_urcu_bp_SOURCES = urcutorture.c
rcutorture_urcu_bp_CFLAGS = -DRCU_BP $(AM_CFLAGS)
rcutorture_urcu_bp_LDADD = $(URCU_BP_LIB)

urcutorture.c: ../common/api.h

.PHONY: regtest

# For now, run the benchmarks too as regression tests.
# TODO: split benchmarks from regression tests
regtest:
	./test_urcu_fork
	./rcutorture_urcu
	./rcutorture_urcu_signal
	./rcutorture_urcu_mb
	./rcutorture_urcu_bp
	./rcutorture_urcu_qsbr
	cd ../benchmark && ./runall.sh && cd ..
