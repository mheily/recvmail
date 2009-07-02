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

SOURCES		 = $(recvmail_SOURCES) $(recvmail_HEADERS)

recvmail_CFLAGS  = -g -O0 -Wall -Werror -include config.h
recvmail_SOURCES = address.c poll.c dnsbl.c \
            recipient.c util.c \
		   log.c mda.c resolver.c socket.c message.c maildir.c session.c \
		   smtp.c server.c throttle.c workqueue.c main.c
recvmail_LDADD   = -lpthread -lresolv
recvmail_HEADERS = address.h  hash.h  mda.h poll.h server.h socket.h    \
    config.h   log.h      message.h  queue.h     session.h  throttle.h  \
    tree.h     protocol.h util.h                                        \
    dnsbl.h    maildir.h  options.h  resolver.h  smtp.h     workqueue.h

loopback:
	printf "helo a\nmail from:abc@def.ghi\nrcpt to:example@example.com\ndata\nSubject: hi\n\nHello\n.\nquit\n" | nc localhost 1025

loopback2:
	/usr/sbin/smtp-source -v -t example@example.com localhost:1025

debug: 
	ulimit -c 999999; rm core; pkill recvmail; make && ( ./recvmail -fv & ) && sleep 1 && echo -e 'helo\nmail from:abc@def.ghi\nrcpt to:test@test.com\nquit' | nc localhost 1025
	test -e /var/mail/core && gdb ./recvmail -c /var/mail/core  || true

nohup:
	rm -f nohup.out
	nohup ./recvmail -fv 2>&1 &

valgrind:
	valgrind --tool=memcheck --leak-check=full --show-reachable=yes --num-callers=20 --track-fds=yes ./recvmail -fq

hammer:
	while [ 1 -eq 1 ] ; do make loopback ; rm /var/spool/recvmail/new/*; done

hammer2:
	time /usr/sbin/smtp-source -s 50 -m 100 -t example@example.com localhost:1025

# Use GNU indent to re-indent the entire source tree
indent:
	indent -orig -ncdb -nfc1 *.[ch]

# Enable Id keyword expansion
svn-fix:
	svn propset svn:keywords Id *.[ch]

# Reformat, diff, and checkin changes
checkin: indent
	svn diff | less
	svn ci

edit:
	gvim *.c *.h Makefile* configure*
