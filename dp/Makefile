TOPDIR = .

SUBDIRS =
# SUBDIRS += third-party
SUBDIRS += utils dpi

TARGET_PROG = dp

SUBDIR_OBJS = utils/$(OBJDIR)/utils.o
SUBDIR_OBJS += dpi/$(OBJDIR)/dpi.o

EXTRA_LDFLAGS = -lpcap -lpcre2-8 -ljansson -ljemalloc -pthread -lurcu -lurcu-cds -lrt -lstdc++ -lm -lnetfilter_queue -lhs -Wl,-rpath,'$$ORIGIN' -Wl,--disable-new-dtags

include $(TOPDIR)/Makefile.rule
