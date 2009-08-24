/*      $Id: socket.c 323 2009-08-23 21:34:14Z mheily $      */

/*
 * Copyright (c) 2008-2009 Mark Heily <devel@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "util.h"

static int socket_tls_read(struct socket *sock);

static SSL_CTX *ssl_ctx;

struct tls_state {
    enum {
        TLS_NOOP,
        TLS_ACCEPT,
        TLS_CONNECT,
        TLS_READ,
        TLS_WRITE,
        TLS_SHUTDOWN,
    } tls_op;
    SSL    *ssl;
}


static int
tls_operation(struct socket *sock, int op)
{
    struct pollfd *pfd;
    int n, retval;

    switch (op) {
        case TLS_NOOP:
            break;

        case TLS_ACCEPT:
            n = SSL_accept(sock->ssl);
            break;

        case TLS_CONNECT:
            n = SSL_connect(sock->ssl);
            break;

        case TLS_READ:
            return socket_tls_read(sock);
            break;

        case TLS_WRITE:
            return socket_tls_write(sock);
            break;

        case TLS_SHUTDOWN:
            n = SSL_shutdown(sock->ssl);
            break;
            
        default:
            log_error("invalid TLS opcode");
            return (-1);
    } 

    switch (SSL_get_error(sock->ssl, n)) {
        case SSL_ERROR_NONE:
            sock->tls_op = TLS_NOOP;
            retval = 0;
            break;

        case SSL_ERROR_ZERO_RETURN:
            log_debug("cannot operate on a closed SSL session");
            sock->tls_op = TLS_NOOP;
            retval = -1;
            break;

        case SSL_ERROR_WANT_READ:
            log_debug("SSL_WANT_READ");
            sock->tls_op = op;
            pfd = socket_get_pollfd(sock);
            pfd->events |= POLLIN;
            retval = 1;
            break;

        case SSL_ERROR_WANT_WRITE:
            log_debug("SSL_WANT_WRITE");
            sock->tls_op = op;
            pfd = socket_get_pollfd(sock);
            pfd->events |= POLLOUT;
            retval = 1;
            break;

        case SSL_ERROR_SYSCALL:
            log_error("SSL syscall error");
            /* Fall through */
        case SSL_ERROR_SSL:
            log_error("SSL protocol error");
            retval = -1;
            break;

        default:
            log_error("unhandled SSL error code");
            /* TODO: dump code */
            abort(); //XXX-BAD BAD BAD
            retval = -1;
    }

    return (retval);
}

static int
socket_tls_read(struct socket *sock)
{
    char buf[SOCK_BUF_SIZE];
    int n, rv;

    n = SSL_read(sock->ssl, &buf[0], sizeof(buf));
/*FIXME error handling*/
    if (n <= 0) {
        switch (SSL_get_error(sock->ssl, n)) {
            case SSL_ERROR_ZERO_RETURN:
                log_debug("zero return");
                rv = -1;
                break;

            case SSL_ERROR_WANT_READ:
                socket_get_pollfd(sock)->events |= POLLIN;
                log_debug("WANT_READ returned");
                rv = 1;
                break;

            case SSL_ERROR_WANT_WRITE:
                socket_get_pollfd(sock)->events |= POLLOUT;
                log_debug("WANT_WRITE returned");
                rv = 1;
                break;

            default:
                log_debug("invalid retval n=%d", n);
                rv = -1;
                break;
        }
        return (rv);
    } else {
        return (parse_lines(sock, buf, (size_t) n));
    }
}

void
tls_free(struct tls_state *tls)
{
    SSL_free(tls->ssl);
}


int
socket_starttls(struct socket *sock)
{
    if ((sock->ssl = SSL_new(ssl_ctx)) == NULL) {
        log_errno("SSL_new() failed");
        return (-1);
    }
    SSL_set_fd(sock->ssl, sock->fd);
    /* SSL-FIXME: set BIO_NOCLOSE on the underlying BIO or there will be multiple close(2) calls */

    return (tls_operation(sock, TLS_ACCEPT));
}

int
tls_init(void)
{
    if (!OPT.ssl_enabled)
        return (0);

    /* OpenSSL transparently seeds the PRNG from /dev/urandom, if it
       exists. Otherwise, it silently fails to seed the PRNG. */
    if (!file_exists("/dev/urandom")) {
        log_error("Unable to seed the PRNG without /dev/urandom.");
        return (-1);
    }

    if (SSL_library_init() < 0)
        return (-1);
    SSL_load_error_strings();
    ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (ssl_ctx == NULL)
        return (-1);

    /* TODO: print the SSL error strings with ERR_error_string(3SSL) */
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, OPT.ssl_certfile) != 1) {
        log_error("unable to load certificate `%s'", OPT.ssl_certfile);
        return (-1);
    }
    log_notice("loaded SSL certificate from `%s'", OPT.ssl_certfile);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, OPT.ssl_keyfile, SSL_FILETYPE_PEM) != 1) {
        log_error("unable to load private key from `%s'", OPT.ssl_keyfile);
        return (-1);
    }
    log_notice("loaded SSL key from `%s'", OPT.ssl_keyfile);

    return (0);
}
