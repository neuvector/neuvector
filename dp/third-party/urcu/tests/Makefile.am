SUBDIRS = common unit benchmark regression

.PHONY: bench regtest

bench:
	cd benchmark && $(MAKE) $(AM_MAKEFLAGS) bench
regtest:
	cd regression && $(MAKE) $(AM_MAKEFLAGS) regtest
