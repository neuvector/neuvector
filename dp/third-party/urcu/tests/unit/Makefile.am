AM_LDFLAGS=-lpthread
AM_CFLAGS=-I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/tests/common -g

noinst_PROGRAMS = test_uatomic \
	test_urcu_multiflavor \
	test_urcu_multiflavor_dynlink

noinst_HEADERS = test_urcu_multiflavor.h

URCU_COMMON_LIB=$(top_builddir)/liburcu-common.la
URCU_LIB=$(top_builddir)/liburcu.la
URCU_QSBR_LIB=$(top_builddir)/liburcu-qsbr.la
URCU_MB_LIB=$(top_builddir)/liburcu-mb.la
URCU_SIGNAL_LIB=$(top_builddir)/liburcu-signal.la
URCU_BP_LIB=$(top_builddir)/liburcu-bp.la
URCU_CDS_LIB=$(top_builddir)/liburcu-cds.la

test_uatomic_SOURCES = test_uatomic.c
test_uatomic_LDADD = $(URCU_COMMON_LIB)

test_urcu_multiflavor_SOURCES = test_urcu_multiflavor.c \
	test_urcu_multiflavor-memb.c \
	test_urcu_multiflavor-mb.c \
	test_urcu_multiflavor-signal.c \
	test_urcu_multiflavor-qsbr.c \
	test_urcu_multiflavor-bp.c
test_urcu_multiflavor_LDADD = $(URCU_LIB) $(URCU_MB_LIB) \
	$(URCU_SIGNAL_LIB) $(URCU_QSBR_LIB) $(URCU_BP_LIB)

test_urcu_multiflavor_dynlink_SOURCES = test_urcu_multiflavor.c \
	test_urcu_multiflavor-memb.c \
	test_urcu_multiflavor-mb.c \
	test_urcu_multiflavor-signal.c \
	test_urcu_multiflavor-qsbr.c \
	test_urcu_multiflavor-bp.c
test_urcu_multiflavor_dynlink_CFLAGS = -DDYNAMIC_LINK_TEST $(AM_CFLAGS)
test_urcu_multiflavor_dynlink_LDADD = $(URCU_LIB) $(URCU_MB_LIB) \
	$(URCU_SIGNAL_LIB) $(URCU_QSBR_LIB) $(URCU_BP_LIB)

check-am:
	./test_uatomic
	./test_urcu_multiflavor
	./test_urcu_multiflavor_dynlink
