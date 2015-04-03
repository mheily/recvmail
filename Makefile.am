#		$Id: $		

#
# Copyright (c) 2004-2007 Mark Heily <devel@heily.com>
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

sbin_PROGRAMS    = recvmail
dist_man8_MANS   = recvmail.8

recvmail_LDADD   = -levent
recvmail_LDFLAGS = $(LIBEVENT_LIBS)
recvmail_CFLAGS  = -Wall -Werror -g -O2 $(LIBEVENT_CFLAGS)
recvmail_SOURCES = address.c domain.c file.c maildir.c smtp.c server.c \
		   recvmail.c recvmail.h

selftest_SOURCES = $(recvmail_SOURCES) selftest.c
selftest_CFLAGS  = $(recvmail_CFLAGS) -DUNIT_TESTING
selftest_LDADD   = $(recvmail_LDADD)
TESTS            = selftest
check_PROGRAMS   = selftest

debug: 
	ulimit -c 999999; rm core; pkill recvmail; make && ( ./recvmail -fv & ) && sleep 1 && echo -e 'helo\nmail from:abc@def.ghi\nrcpt to:test@test.com\nquit' | nc localhost 1025
	test -e /var/mail/core && gdb ./recvmail -c /var/mail/core  || true

hammer:
	while [ 1 -eq 1 ] ; do echo -e 'helo\nmail from:a@b.com\nrcpt to:test@test.com\ndata\nhi\n.\nquit' | nc localhost 1025 ; rm /srv/mail/store/test.com/test/new/*; done


