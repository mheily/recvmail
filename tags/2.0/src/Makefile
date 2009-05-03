#		$Id: Makefile 8 2007-12-10 04:23:10Z mheily $
#
# Copyright (c) 2007 Mark Heily <mark@heily.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Differences btwn Automake and mconf:
#   - man_MANS are considered source and included in `make dist'
#     do not use dist_man_MANS
#   - man1_MANS, man2_MANS, etc., are not supported; use man_MANS instead
#   - Use CFLAGS instead of AM_CFLAGS
#   HAVE_CONFIG_H is not defined and should not be used in program sources.
#   A global SOURCES variable is required, and should contain a list of
#   all source code files in the project.

default: build

include config.mk

# Default values for standard variables
#
CC ?=		cc
LD ?=		ld

FILES = 	$(SOURCES) $(EXTRA_DIST) $(man_MANS) \
		$(data_DATA) $(pkgdata_DATA) \
		configure configure.in config.mk Makefile.am Makefile
MAJOR = 	`echo $(VERSION) | awk -F. '{ $$1 }'`
LDFLAGS = 	-shared -soname=lib$@.so.$(MAJOR)
DISTDIR = 	$(PACKAGE)-$(VERSION)

# Prepend the 'DESTDIR' variable to all installation paths
#
LIBDIR := $(DESTDIR)$(LIBDIR)
BINDIR := $(DESTDIR)$(BINDIR)
SBINDIR := $(DESTDIR)$(SBINDIR)
INCLUDEDIR := $(DESTDIR)$(INCLUDEDIR)
DATADIR := $(DESTDIR)$(DATADIR)
PKGDATADIR := $(DESTDIR)$(PKGDATADIR)
MANDIR := $(DESTDIR)$(MANDIR)

include Makefile.am

build: config.h subdir-stamp $(lib_LIBRARIES) $(bin_PROGRAMS) $(sbin_PROGRAMS) $(data_DATA) $(pkgdata_DATA)
	@true

subdir-stamp:
	for subdir in $(SUBDIRS) ; do \
	   cd $$subdir ; \
	   if [ -x ./configure ] ; then ./configure ; fi ; \
	   make ; \
	done
	touch subdir-stamp

config.h:
	./configure 

$(bin_PROGRAMS) $(sbin_PROGRAMS) $(check_PROGRAMS) : $(SOURCES)
	$(CC) $(CFLAGS) $($(@)_CFLAGS) -o $@ $($(@)_SOURCES) $($(@)_LDADD)

$(lib_LIBRARIES) : $(SOURCES)
	$(CC) $(CFLAGS) $($(@)_CFLAGS) -fPIC -c \
		$($(@)_SOURCES) $($(@)_LDADD)
	$(LD) $(LDFLAGS) $($(@)_LDFLAGS) -o lib$@.so.$(VERSION)	\
		`echo $($(@)_SOURCES) | sed 's/\.c/\.o/g'`
	ar rs lib$(@).a *.o

clean:
	rm -f $(bin_PROGRAMS) $(sbin_PROGRAMS) subdir-stamp *.o 

distclean: clean
	rm -f config.mk config.sym config.h

check: $(check_PROGRAMS)
	for prog in $(TESTS) ; do ./$$prog ; done

dist: 
	if [ -d $(DISTDIR) ] ; then \
		cd $(DISTDIR) && rm -f $(FILES) && cd .. && rmdir $(DISTDIR) ; \
	fi
	mkdir $(DISTDIR)
	cp $(FILES) $(DISTDIR)
	tar zcvf $(PACKAGE)-$(VERSION).tar.gz $(DISTDIR)
	cd $(DISTDIR) && rm -f $(FILES)
	rmdir $(DISTDIR)


install: build
	for lib in $(lib_LIBRARIES) 				; \
	do 							  \
	  library=lib$$lib.so.$(VERSION)			; \
	  install -Ds -m 644 $$library $(LIBDIR)/$$library 	; \
	  ln -s $$library $(LIBDIR)/lib$$lib.so.$(MAJOR)	; \
	done
	for bin in $(bin_PROGRAMS) 				; \
	  do install -D -m 755 $$bin $(BINDIR)/$$bin		; \
	done
	for sbin in $(sbin_PROGRAMS) 				; \
	  do install -D -m 755 $$sbin $(SBINDIR)/$$sbin		; \
	done
	for hdr in $(include_HEADERS) 				; \
	  do install -D -m 644 $$hdr $(INCLUDEDIR)/$$hdr	; \
	done
	for man in $(man_MANS) $(dist_man_MANS)			; \
	do 							  \
	  section=`echo $$man | sed 's,.*\\.,,'` ; \
	  install -D -m 644 $$man $(MANDIR)/man$$section/$$man ; \
	  gzip -f $(MANDIR)/man$$section/$$man ; \
	done
	for data in $(data_DATA) 				; \
	  do install -D -m 644 $$data $(DATADIR)/$$data		; \
	done
	for data in $(pkgdata_DATA) 				; \
	  do install -D -m 644 $$data $(PKGDATADIR)/$$data	; \
	done
	if [ `id -u` -eq '0' ] ; then ldconfig ; fi
