if HAVE_DOXYGEN

doc_srcs = $(shell find $(top_srcdir)/src -name '*.c')

doxyfile.stamp: $(doc_srcs) Makefile.am
	rm -rf html man

# Test for running under make distcheck.
# If so, sibling src directory will be empty:
# move it out of the way and symlink the real one while we run doxygen.
	[ -f ../src/Makefile.in ] || \
{ set -x; cd ..; mv src src.distcheck; ln -s $(top_srcdir)/src; }

	cd ..; doxygen doxygen.cfg >/dev/null

	[ ! -d ../src.distcheck ] || \
{ set -x; cd ..; rm src; mv src.distcheck src; }

# We need to use bash for its associative array facility
# (`bash -p` prevents import of functions from the environment).
# The command has to be a single line so the functions work
# and so `make` gives all lines to `bash -c`
# (hence ";\" at the end of every line but the last).
	/bin/bash -p -c 'declare -A renamed_page;\
main(){ set -e; cd man/man3; rm -f _*;\
  count_real_pages;\
  rename_real_pages;\
  make_symlinks;\
};\
count_real_pages(){ page_count=0;\
  for i in $$(ls -S);\
  do head -n1 $$i | grep -E -q '^\.so' && break;\
    page_count=$$(($$page_count + 1));\
  done;\
  first_link=$$(($$page_count + 1));\
};\
rename_real_pages(){ for i in $$(ls -S | head -n$$page_count);\
  do for j in $$(ls -S | tail -n+$$first_link);\
    do grep -E -q $$i$$ $$j && break;\
    done;\
    mv -f $$i $$j;\
    renamed_page[$$i]=$$j;\
  done;\
};\
make_symlinks(){ for j in $$(ls -S | tail -n+$$first_link);\
  do ln -sf $${renamed_page[$$(cat $$j | cut -f2 -d/)]} $$j;\
  done;\
};\
main'

	touch doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doxygen/man $(top_srcdir)/doxygen/html
install-data-local:
	mkdir -p $(DESTDIR)$(mandir)/man3
	cp --no-dereference --preserve=links,mode,timestamps man/man3/*.3\
	  $(DESTDIR)$(mandir)/man3/

# make distcheck needs uninstall-local
uninstall-local:
	rm -r $(DESTDIR)$(mandir) man html doxyfile.stamp
endif
