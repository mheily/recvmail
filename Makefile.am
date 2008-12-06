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
man_MANS         = recvmail.8

SOURCES		 = $(recvmail_SOURCES) $(selftest_SOURCES)

recvmail_CFLAGS  = -g -O2 -Wall -Werror
recvmail_SOURCES = address.c atomic.c aliases.c file.c message.c maildir.c session.c smtp.c server.c recvmail.c 
recvmail_HEADERS = recvmail.h queue.h

selftest_SOURCES = $(recvmail_SOURCES) selftest.c
selftest_CFLAGS  = $(recvmail_CFLAGS) -DUNIT_TESTING
selftest_LDADD   = $(recvmail_LDADD)
TESTS            = selftest
check_PROGRAMS   = selftest

loopback:
	printf 'helo\nmail from:abc@def.ghi\nrcpt to:test@test.com\ndata\nSubject: hi\n\nHello\n.\nquit\n' | nc localhost 1025
	printf 'GET /test HTTP/1.1\nConnection: close\n\n' | nc localhost 8025

debug: 
	ulimit -c 999999; rm core; pkill recvmail; make && ( ./recvmail -fv & ) && sleep 1 && echo -e 'helo\nmail from:abc@def.ghi\nrcpt to:test@test.com\nquit' | nc localhost 1025
	test -e /var/mail/core && gdb ./recvmail -c /var/mail/core  || true

valgrind:
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./recvmail -fv -p 1025

hammer:
	while [ 1 -eq 1 ] ; do make loopback ; rm /var/recvmail/store/test.com/test/new/*; done

# Use GNU indent to re-indent the entire source tree
indent:
	indent -orig -ncdb -nfc1 *.[ch]

# Reformat, diff, and checkin changes
checkin: indent
	svn diff | less
	svn ci

edit:
	gvim *.c *.h Makefile* configure*
