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
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "recvmail.h"

static ssize_t  socket_readln(char **, struct socket *);
static void socket_free(struct socket *sock);
static void socket_read(void *);
static void buf_drain(struct socket *);
static int buf_append(struct socket *sock, const char *buf, size_t len);
static struct line * line_new(const char *buf, size_t len);
static void _socket_cancel_read(void *arg);
static void _socket_cancel_write(void *arg);

/* The maximum length of a single line (32 MB) */
static const size_t SOCK_LINE_MAX = (INT_MAX >> 6);

/* The buffer size of a socket */
#define SOCK_BUF_SIZE   16384

struct line {
    STAILQ_ENTRY(line) entry;
    size_t  off, 
            len;
    char    buf[];
};

/* A socket buffer */
struct socket {
    int         status;     /* 0=socket OK, -1=error condition */
    short       poll_events; /* POLLIN | POLLOUT */
    int         fd;
    struct session      *sess;
    struct protocol     *proto;
    dispatch_source_t    ds_read, 
                         ds_write;
    struct sockaddr_storage peer;
    char peername[INET6_ADDRSTRLEN];
    /* TODO: struct tls_state *tls; */
    STAILQ_HEAD(,line) input;
    STAILQ_HEAD(,line) output;
    struct line *input_tmp;
};

#define LINE_IS_FRAGMENTED(x) ((x)->buf[(x)->len - 1] != '\n')

static struct line *
line_new(const char *buf, size_t len)
{
    struct line *x;
    size_t cnt;

    if (len > SOCK_LINE_MAX) {
        log_error("line too long");
        return (NULL);
    }
    cnt = sizeof(*x) + len + 1;
    x = malloc(cnt);
    if (x == NULL) {
        log_errno("malloc(3) unable to alloc %zu bytes", cnt);
        return (NULL);
    }
    memset(x, 0, sizeof(*x));
    memcpy(&x->buf, buf, len);
    x->buf[len] = '\0';
    x->len = len;
    
    return (x);
}

#if DEADWOOD
int
socket_event_handler(struct socket *sock, int events)
{
#if TODO
    /* Attempt to retry any incomplete TLS operation */
    if ((sock->ssl != NULL) && 
            (sock->tls_op != TLS_NOOP) && 
            (events & POLLIN || events & POLLOUT)) 
    {
        return (tls_operation(sock, sock->tls_op));
    }
#endif

    if (events & POLLHUP) {
        // FIXME: read any data remaining in the kernel buffer
        log_debug("fd %d hangup", sock->fd);
        return (0);
    }
    if (events & POLLIN) {
        log_debug("fd %d ready for reading", sock->fd);
        return (socket_read(sock));
    }
    if (events & POLLOUT) {
        log_debug("fd %d ready for writing", sock->fd);
        return (buf_drain(sock));
    }

    return (0);
}
#endif

static int
append_input(struct socket *sock, const char *buf, size_t len)
{
    struct line *x, *tail;

    if (len == 0 || len > SOCK_LINE_MAX) {
        log_error("invalid line length %zu", len);
        return (-1);
    }

    tail = STAILQ_LAST(&sock->input, line, entry);
    if (tail != NULL && LINE_IS_FRAGMENTED(tail)) {
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
        
        STAILQ_REMOVE(&sock->input, tail, line, entry);
    } else {
        if ((x = line_new(buf, len)) == NULL) {
            log_errno("malloc(3)");
            return (-1);
        }
    }

    STAILQ_INSERT_TAIL(&sock->input, x, entry);
    log_debug("<<< %zu: `%s'", len,  &x->buf[0]);

    return (0);
}

struct socket *
socket_new(int fd, struct session *sess, struct protocol *proto)
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
    sock->proto = proto;
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

    sock->ds_read = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, dispatch_get_main_queue());
    if (sock->ds_read == NULL) {
        log_errno("dispatch_source_create");
        goto errout;
    }
    dispatch_set_context(sock->ds_read, sock);
    dispatch_source_set_event_handler_f(sock->ds_read, socket_read);
    dispatch_source_set_cancel_handler_f(sock->ds_read, _socket_cancel_read);

    sock->ds_write = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, fd, 0, dispatch_get_main_queue());
    if (sock->ds_write == NULL) {
        log_errno("dispatch_source_create");
        goto errout;
    }
    dispatch_set_context(sock->ds_write, sock);
    dispatch_source_set_event_handler_f(sock->ds_write, (dispatch_function_t) buf_drain);
    dispatch_source_set_cancel_handler_f(sock->ds_write, _socket_cancel_write);

    socket_poll(sock, POLLIN);

    return (sock);

errout:
    free(sock);
    return (NULL);
}

static void
_socket_cancel(void *arg, short events)
{
    struct socket *sock = (struct socket *) arg;

    log_debug("disabling events on socket %d", sock->fd);
    sock->poll_events ^= events;
    if (sock->poll_events == 0) {
        (void) close(sock->fd);
        if (sock->sess != NULL)
            free(sock->sess);
        socket_free(sock);
    }
}

static void
_socket_cancel_read(void *arg)
{
    return _socket_cancel(arg, POLLIN);
}

static void
_socket_cancel_write(void *arg)
{
    return _socket_cancel(arg, POLLOUT);
}

int
socket_close(struct socket *sock)
{
    if (sock->status < 0) {
        log_error("attempt to close a socket multiple times");
        return (0);
    }
    sock->status = -1;
    if (sock->poll_events & POLLIN)
            dispatch_source_cancel(sock->ds_read);
    if (sock->poll_events & POLLOUT)
            dispatch_source_cancel(sock->ds_write);
    return (0);
}

static void
socket_free(struct socket *sock)
{
    struct line *n1, *n2;

    if (sock == NULL) {
        log_error("double free");
        return;
    }
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

#ifdef TODO
    if (sock->ssl != NULL)
        tls_free(sock->tls);
#endif

    free(sock);
}

static ssize_t
socket_readln(char **dst, struct socket *sock)
{
    struct line *x;

    /* Read data from the socket*/
    socket_read(sock);
    if (0) {  /* FIXME-XXX: need to check an error flag */
        log_error("socket_read() failed");
        *dst = NULL;
        return (-1);
    } 

    /* Destroy the previous line */
    free(sock->input_tmp);
    sock->input_tmp = NULL;

    /* Return the first string */
    if (! STAILQ_EMPTY(&sock->input) ) {
        x = STAILQ_FIRST(&sock->input);
        log_debug("x=%p len=%zu buf=`%s'", x, x->len, x->buf);
        if (LINE_IS_FRAGMENTED(x)) {
            log_debug("fragmented line");
            *dst = NULL;
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
socket_poll(struct socket *sock, short events)
{
    int rv;

    switch (events) {
        case POLLIN:
            if (sock->poll_events & POLLOUT) {
                sock->poll_events ^= POLLOUT;
                dispatch_suspend(sock->ds_write);
            }
            sock->poll_events |= POLLIN;
            dispatch_resume(sock->ds_read);
            log_debug("enabled POLLIN on socket %d", sock->fd);
            rv = 0;
            break;
        case POLLOUT:
            if (sock->poll_events & POLLIN) {
                sock->poll_events ^= POLLIN;
                dispatch_suspend(sock->ds_read);
            }
            sock->poll_events |= POLLOUT;
            dispatch_resume(sock->ds_write);
            log_debug("enabled POLLOUT on socket %d", sock->fd);
            rv = 0;
            break;
        default:
            log_error("invalid events: %d", events);
            rv = -1;
            break;
    }

    return (rv);
}

static void
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
            sock->status = -1;
            return;
        }

        /* Create a new line object */
        if (append_input(sock, &buf[a], line_len) < 0) {
            sock->status = -1;
            return;
        }

        a = z + 1;
    }

    /* Save any remaining line fragment */
    /* TODO: avoid code duplication with above loop */
    if (a != buf_len) {
        line_len = z - a;
        if (append_input(sock, &buf[a], line_len) < 0) {
            sock->status = -1;
            return;
        }
    }
}

static void
socket_read(void *arg)
{
    struct socket *sock = (struct socket *) arg;
    char buf[SOCK_BUF_SIZE];
    char *p;
    ssize_t n;

    log_debug("reading from socket (fd=%d)", sock->fd);

#if TODO
    if (sock->ssl != NULL)
        return (socket_tls_read(sock));
#endif
    
    /* Read as much as possible from the kernel socket buffer. */
    n = recv(sock->fd, &buf[0], sizeof(buf), 0);
    if (n < 0) { 
        if (errno == EAGAIN) {
            log_debug("got EAGAIN");
            return;
        } else if (errno == ECONNRESET) {
            log_info("connection reset by peer");   //TODO: add remote_addr
            sock->status = -1;
            return;
        } else {
            log_errno("recv(2)");
            sock->status = -1;
            return;
        }
    }

    /* Check for EOF */
    /* TODO - verify: is n==0 actually EOF? */
    if (n == 0) {
        log_debug("zero-length read(2)");
        //TODO -- indicate to session object that no more reads are possible
        sock->status = -1;
        return;
    }
    log_debug("read %zu bytes", n);

    parse_lines(sock, buf, (size_t) n);
    while (! STAILQ_EMPTY(&sock->input) ) {
        n = socket_readln(&p, sock);
        if (n < 0) {
            socket_close(sock);
            return;
        }
        sock->proto->read_hook(sock->sess, p, n);
        if (sock->status < 0) {
            socket_close(sock);
            return;
        }
    }
} 

static int
line_send(struct socket *sock, struct line *ent)
{
    ssize_t n;

    n = send(sock->fd, ent->buf + ent->off, ent->len, 0);
    if (n < 0) {
        if (errno == EAGAIN) {
            socket_poll(sock, POLLOUT);
            return (1);
        }

        /* TODO: if (errno == ECONNRESET) ... */
        log_errno("send(2)");
        return (-1);
    }
    if (n < ent->len) {
        ent->off += n;
        ent->len -= n;
        socket_poll(sock, POLLOUT);
        return (1);
    }
   
    return (0);        
}

static void
buf_drain(struct socket *sock)
{
    struct line *cur, *nxt;
    int rv;

    log_debug("draining output buffer for socket %d", sock->fd);
    socket_poll(sock, POLLIN);

    cur = STAILQ_FIRST(&sock->output); 
    while (cur != NULL) {
        nxt = STAILQ_NEXT(cur, entry);   
        rv = line_send(sock, cur);
        if (rv < 0) {
            sock->status = -1;
            return;
        }
        if (rv == 1)
            return;
        free(cur);
        cur = nxt;
    }
    
    STAILQ_INIT(&sock->output);
}

static int
buf_append(struct socket *sock, const char *buf, size_t len)
{
    struct line *x;

    if ((x = line_new(buf, len)) == NULL) 
        return (-1);
    socket_poll(sock, POLLOUT);
    STAILQ_INSERT_TAIL(&sock->output, x, entry);

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

    /* If there is anything in the output buffer,
     * assume that the socket is not ready for writing.
     */
    if (!STAILQ_EMPTY(&sock->output))
        return buf_append(sock, buf, len);

    n = send(sock->fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN) {
            socket_poll(sock, POLLOUT);
            return (buf_append(sock, buf, len));
        }
        /* TODO: if (errno == ECONNRESET) ... */
        log_errno("send(2)");
        return (-1);
    }
    if (n < len) {
        socket_poll(sock, POLLOUT);
        return (buf_append(sock, buf + n, len - n));
    }

    return (0);
}

int
socket_pending(const struct socket *sock)
{
    return (!STAILQ_EMPTY(&sock->input));
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
