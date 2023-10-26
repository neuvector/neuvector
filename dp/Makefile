TOPDIR = .

SUBDIRS =
SUBDIRS += utils dpi

TARGET_PROG = dp

SUBDIR_OBJS = utils/$(OBJDIR)/utils.o
SUBDIR_OBJS += dpi/$(OBJDIR)/dpi.o

ifeq ($(ARCH), arm64)
STATIC_LIBS = third-party/.objs/arm64/lib/libhs.a

EXTRA_LDFLAGS = -lpcap -lpcre2-8 -ljansson -ljemalloc
else
SUBDIR_OBJS += objects/libpcap/*.o

STATIC_LIBS = third-party/.objs/lib/libjansson.a
STATIC_LIBS += third-party/.objs/lib/libjemalloc.a
STATIC_LIBS += third-party/.objs/lib/timeout.a
STATIC_LIBS += third-party/.objs/lib/libpcre2-8.a
STATIC_LIBS += third-party/.objs/lib/x86_64-linux-gnu/libhs.a

endif

EXTRA_LDFLAGS += -pthread -lurcu -lurcu-cds -lrt -lstdc++ -lm -lnetfilter_queue -Wl,-rpath,'$$ORIGIN' -Wl,--disable-new-dtags

include $(TOPDIR)/Makefile.rule
