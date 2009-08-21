/*      $Id$      */

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

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "socket.h"
#include "poll.h"
#include "options.h"
#include "queue.h"
#include "log.h"
#include "util.h"

static int socket_read(struct socket *sock);
static int socket_tls_read(struct socket *sock);

static SSL_CTX *ssl_ctx;

/* The maximum line length (based on SMTP_LINE_MAX) */
// TODO: don't need 2 identical constants
#define SOCK_LINE_MAX   1000

/* The buffer size of a socket */
#define SOCK_BUF_SIZE   16384

struct line {
    STAILQ_ENTRY(line) entry;
    size_t len;
    char buf[];
};

/* A socket buffer */
struct socket {
    int     fd;
    struct watch *wd;
    struct sockaddr_storage peer;
    char peername[INET6_ADDRSTRLEN];
    enum {
        TLS_NOOP,
        TLS_ACCEPT,
        TLS_CONNECT,
        TLS_READ,
        TLS_WRITE,
        TLS_SHUTDOWN,
    } tls_op;
    struct session *sess;
    SSL    *ssl;
    STAILQ_HEAD(,line) input;
    STAILQ_HEAD(,line) output;  //TODO:not used yet
    struct line *input_tmp;
};

#define LINE_FRAGMENTED(x) ((x)->buf[(x)->len - 1] != '\n')

static int
tls_operation(struct socket *sock, int op)
{
    int n, retval, events;

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
            abort(); //TODO:fixme
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
            events = socket_poll_get(sock);
            events |= POLLIN;
            socket_poll_set(sock, events);
            retval = 1;
            break;

        case SSL_ERROR_WANT_WRITE:
            log_debug("SSL_WANT_WRITE");
            sock->tls_op = op;
            events = socket_poll_get(sock);
            events |= POLLOUT;
            socket_poll_set(sock, events);
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

int
socket_event_handler(struct socket *sock, int events)
{
    if (events & POLLHUP) {
        // FIXME: read any data remaining in the kernel buffer
        return (0);
    }

    /* Attempt to retry any incomplete TLS operation */
    if ((sock->ssl != NULL) && 
            (sock->tls_op != TLS_NOOP) && 
            (events & POLLIN || events & POLLOUT)) 
    {
        return (tls_operation(sock, sock->tls_op));
    }

#if TODO
    // TODO: implement output buffreing
    if (events & POLLOUT) {
        if (s->fd < 0) 
            log_debug("fd %d is writable (session terminated)", s->fd);
        else
            log_debug("fd %d is now writable", s->fd);
        //TODO - flush output buffer, or do something
    }
#endif

    return (0);
}

static int
append_input(struct socket *sock, const char *buf, size_t len)
{
    struct line *x, *tail;

    if (len == 0 || len > SOCK_LINE_MAX) {
        log_error("invalid line length %zu", len);
        return (-1);
    }

    tail = STAILQ_LAST(&sock->input, line, entry);
    if (tail != NULL && LINE_FRAGMENTED(tail)) {
        STAILQ_REMOVE(&sock->input, tail, line, entry);

        /* Create a new line large enough to contain both fragments */
        x = malloc(sizeof(*x) + len + tail->len + 1);
        if (x == NULL) {
            log_errno("malloc(3)");
            return (-1);
        }

        /* Merge the two fragments into a single line */
        x->len = tail->len + len;
        memcpy(&x->buf, tail->buf, tail->len);
        memcpy(&x->buf[tail->len], buf, len);
        x->buf[x->len] = '\0';

    } else {
        x = malloc(sizeof(*x) + len + 1);
        if (x == NULL) {
            log_errno("malloc(3)");
            return (-1);
        }
        memcpy(&x->buf, buf, len);
        x->buf[len] = '\0';
        x->len = len;
    }

    STAILQ_INSERT_TAIL(&sock->input, x, entry);
    log_debug("<<< %zu: `%s'", len,  &x->buf[0]);

    return (0);
}

struct socket *
socket_new(int fd, struct session *sess)
{
    struct socket *sock = NULL;
    const int bufsz = SOCK_BUF_SIZE;
	socklen_t cli_len = sizeof(sock->peer);
    int rv;

    /* Set the kernel socket buffer size */
    if (setsockopt(fd, SOL_SOCKET, 
                SO_SNDBUF, (char *)&bufsz, sizeof(bufsz)) < 0) {
        log_errno("setsockopt(2)");
        goto errout;
    }
    if (setsockopt(fd, SOL_SOCKET, 
                SO_RCVBUF, (char *)&bufsz, sizeof(bufsz)) < 0) {
        log_errno("setsockopt(2)");
        goto errout;
    }
 
    /* Use non-blocking I/O */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        log_errno("fcntl(2)");
        goto errout;
    }

    /* Initialize the object */
    sock = calloc(1, sizeof(*sock));
    if (sock == NULL) {
        log_errno("malloc(3)");
        return (NULL);
    }
    sock->fd = fd;
    sock->sess = sess;
    STAILQ_INIT(&sock->input);
    STAILQ_INIT(&sock->output);

    /* Get the peer socket address */
    if (getpeername(fd, (struct sockaddr *) &sock->peer, &cli_len) < 0) {
            log_errno("getpeername(3) of fd %d", fd);
            goto errout;
    }

    /* Generate a human-readable representation of the remote address */
    rv = getnameinfo((struct sockaddr *) &sock->peer, cli_len, 
            &sock->peername[0], sizeof(sock->peername), 
            NULL, 0, NI_NUMERICHOST);
    if (rv != 0) {
            log_errno("getnameinfo(3): %s", gai_strerror(rv));
            goto errout;
    }

    return (sock);

errout:
    free(sock);
    return (NULL);
}

int
socket_close(struct socket *sock)
{
    if (sock->fd < 0) {
        log_error("attempt to close a socket multiple times");
        return (0);
    }
    if (sock->wd != NULL) {
        poll_remove(sock->wd);
        sock->wd = NULL;
    }
    if (close(sock->fd) < 0) {
        log_errno("close(3) of fd %d", sock->fd);
        return (-1);
    }
    sock->fd = -1;
    return (0);
}

void
socket_free(struct socket *sock)
{
    struct line *n1, *n2;

    if (sock == NULL) {
        log_error("double free");
        return;
    }
    if (sock->wd != NULL)
        poll_remove(sock->wd);
    if (sock->fd >= 0)
        (void) close(sock->fd); 

    /* Destroy all items in the input buffer */
    n1 = STAILQ_FIRST(&sock->input);
    while (n1 != NULL) {
        n2 = STAILQ_NEXT(n1, entry);
        free(n1);
        n1 = n2;
    }
    free(sock->input_tmp);

    /* Destroy all items in the output buffer */
    n1 = STAILQ_FIRST(&sock->output);
    while (n1 != NULL) {
        n2 = STAILQ_NEXT(n1, entry);
        free(n1);
        n1 = n2;
    }

    if (sock->ssl != NULL)
        SSL_free(sock->ssl);

    free(sock);
}

ssize_t
socket_readln(char **dst, struct socket *sock)
{
    struct line *x;

    *dst = NULL;

    /* Read data from the socket*/
    if (socket_read(sock) < 0) {
            log_error("socket_read() failed");
            return (-1);
    } 

    /* Destroy the previous line */
    free(sock->input_tmp);
    sock->input_tmp = NULL;

    /* Return the first string */
    if (! STAILQ_EMPTY(&sock->input) ) {
        x = STAILQ_FIRST(&sock->input);
        log_debug("x=%p len=%zu buf=`%s'", x, x->len, x->buf);
        if (LINE_FRAGMENTED(x)) {
            log_debug("fragmented line");
            return (0);
        }
        STAILQ_REMOVE_HEAD(&sock->input, entry);
        *dst = &x->buf[0];
        sock->input_tmp = x;
        return (x->len);
    }
    
    return (0);
}

int
socket_poll_enable(struct socket *sock, 
        int events,
        void (*callback)(void *, int), 
        void *udata)
{
    if (sock->wd != NULL) {
        log_error("multiple attempts to enable polling on a socket");
        return (-1);
    }
    sock->wd = poll_add(sock->fd, events, callback, udata);
    return ((sock->wd == NULL) ? -1 : 0);
}

int
socket_poll_disable(struct socket *sock)
{
    if (sock->wd == NULL) {
        log_error("cannot disable polling on this socket");
        return (-1);
    }
    poll_remove(sock->wd);
    sock->wd = NULL;
    return (0);
}

static int
parse_lines(struct socket *sock, char *buf, size_t buf_len)
{
    size_t line_len, a, z;

    log_debug("buf_len=%zu", buf_len);

    /* Divide the buffer into lines. */
    for (a = z = 0; z < buf_len; z++) {

        if (buf[z] != '\n') 
            continue;

        /* Compute the line length including the trailing LF. */
        line_len = z - a + 1;

        /* Convert CR+LF to LF line endings. */
        if (line_len > 0 && buf[z - 1] == '\r') {
            line_len--;
            buf[z - 1] = '\n';
        }
        if (line_len >= SOCK_LINE_MAX) {
            log_error("line length exceeded");
            return (-1);
        }

        /* Create a new line object */
        if (append_input(sock, &buf[a], line_len) < 0)
            return (-1);

        a = z + 1;
    }

    /* Save any remaining line fragment */
    /* TODO: avoid code duplication with above loop */
    if (a != buf_len) {
        line_len = z - a;
        if (append_input(sock, &buf[a], line_len) < 0)
            return (-1);
    }

    return (0);
}

static int
socket_tls_read(struct socket *sock)
{
    char buf[SOCK_BUF_SIZE];
    int n, rv, events;

    n = SSL_read(sock->ssl, &buf[0], sizeof(buf));
/*FIXME error handling*/
    if (n <= 0) {
        switch (SSL_get_error(sock->ssl, n)) {
            case SSL_ERROR_ZERO_RETURN:
                log_debug("zero return");
                rv = -1;
                break;

            case SSL_ERROR_WANT_READ:
                events = socket_poll_get(sock);
                events |= POLLIN;
                socket_poll_set(sock, events);
                log_debug("WANT_READ returned");
                rv = 1;
                break;

            case SSL_ERROR_WANT_WRITE:
                events = socket_poll_get(sock);
                events |= POLLOUT;
                socket_poll_set(sock, events);
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

static int
socket_read(struct socket *sock)
{
    char buf[SOCK_BUF_SIZE];
    ssize_t n;

    if (sock->ssl != NULL)
        return (socket_tls_read(sock));

    /* Read as much as possible from the kernel socket buffer. */
    n = recv(sock->fd, &buf[0], sizeof(buf), 0);
    if (n < 0) { 
        if (errno == EAGAIN) {
            log_debug("got EAGAIN");
            return (0);
        } else if (errno == ECONNRESET) {
            log_info("connection reset by peer");   //TODO: add remote_addr
            return (-1);
        } else {
            log_errno("recv(2)");
            return (-1);
        }
    }

    /* Check for EOF */
    /* TODO - verify: is n==0 actually EOF? */
    if (n == 0) {
        log_debug("zero-length read(2)");
        //TODO -- indicate to session object that no more reads are possible
        return (-1);
    }
    log_debug("read %zu bytes", n);

    return parse_lines(sock, buf, (size_t) n);
} 

static int
socket_buffer_write(struct socket *sock, const char *buf, size_t len)
{
    struct line *x;

    /* Copy the buffer to a <line> object */
    x = malloc(sizeof(*x) + len + 1);
    if (x == NULL) {
        log_errno("malloc(3)");
        return (-1);
    }
    memcpy(&x->buf, buf, len);
    x->buf[len] = '\0';
    x->len = len;

    STAILQ_INSERT_TAIL(&sock->output, x, entry);
    /* FIXME: enable poll() for POLLOUT */
    return (0);
}

int
socket_write(struct socket *sock, const char *buf, size_t len)
{
    ssize_t n;

    /* If the file descriptor is closed, do nothing */
    /* TODO: use a status flag instead of checking for -1 */
    if (sock->fd < 0)
        return (0);

#if FIXME
    if (!sock->can_write)
        return socket_buffer_write(sock, buf, len);
#endif
    
    n = send(sock->fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN) 
            return socket_buffer_write(sock, buf, len);
        /* TODO: if (errno == ECONNRESET) ... */
        log_errno("send(2)");
        return (-1);
    }
    if (n < len) {
        /* TODO: this is probably impossible for sockets */
        log_errno("send(2) - short write");
        return (-1);
    }

    return (0);
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
socket_pending(const struct socket *sock)
{
    return (STAILQ_EMPTY(&sock->input));
}

int
socket_get_family(const struct socket *sock)
{
    return (sock->peer.ss_family);
}

int
socket_get_peeraddr4(const struct socket *sock)
{
    struct sockaddr_in *sain = (struct sockaddr_in *) &sock->peer;
    return (sain->sin_addr.s_addr);
}

const char *
socket_get_peername(const struct socket *sock)
{
    return ((const char *) &sock->peername);
}

void
socket_poll_set(struct socket *s, int flags)
{
    poll_modify(s->wd, flags);
}

int
socket_poll_get(const struct socket *s)
{
    return (poll_events_get(s->wd));
}

static int
socket_tls_init(void)
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

int
socket_init(void)
{
    if (socket_tls_init() < 0) {
        log_error("unable to initialize TLS subsystem");
        return (-1);
    }

    return (0);
}
