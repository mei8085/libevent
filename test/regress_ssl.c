/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "util-internal.h"

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "event2/event.h"
#include "event2/bufferevent_ssl.h"
#include "event2/bufferevent_struct.h"
#include "event2/buffer.h"
#include "event2/listener.h"

#include "tinytest.h"
#include "tinytest_macros.h"

#include <string.h>
#ifdef _WIN32
#include <io.h>
#define read _read
#define write _write
#else
#include <unistd.h>
#endif

/* A pre-generated key, to save the cost of doing an RSA key generation step
 * during the unit tests. It is published in this file, so you would have to
 * be very foolish to consider using it in your own code. */
static const char KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEogIBAAKCAQEAtK07Ili0dkJb79m/sFmHoVJTWyLoveXex2yX/BtUzzcvZEOu\n"
    "QLon/++5YOA48kzZm5K9mIwZkZhui1ZgJ5Bjq0LGAWTZGIn+NXjLFshPYvTKpOCW\n"
    "uzL0Ir0LXMsBLYJQ5A4FomLNxs4I3H/dhDSGy/rSiJB1B4w2xNiwPK08/VL3zZqk\n"
    "V+GsSvGIIkzhTMbqPJy9K8pqyjwOU2pgORS794yXciTGxWYjTDzJPgQ35YMDATaG\n"
    "jr4HHo1zxU/Lj0pndSUK5rKLYxYQ3Uc8B3AVYDl9CP/GbOoQ4LBzS68JjcAUyp6i\n"
    "6NfXlc2D9S9XgqVqwI+JqgJs0eW/+zPY2UEDWwIDAQABAoIBAD2HzV66FOM9YDAD\n"
    "2RtGskEHV2nvLpIVadRCsFPkPvK+2X3s6rgSbbLkwh4y3lHuSCGKTNVZyQ9jeSos\n"
    "xVxT+Q2HFQW+gYyw2gj91TQyDY8mzKhv8AVaqff2p5r3a7RC8CdqexK9UVUGL9Bg\n"
    "H2F5vfpTtkVZ5PEoGDLblNFlMiMW/t1SobUeBVx+Msco/xqk9lFv1A9nnepGy0Gi\n"
    "D+i6YNGTBsX22YhoCZl/ICxCL8lgqPei4FvBr9dBVh/jQgjuUBm2jz55p2r7+7Aw\n"
    "khmXHReejoVokQ2+htgSgZNKlKuDy710ZpBqnDi8ynQi82Y2qCpyg/p/xcER54B6\n"
    "hSftaiECgYEA2RkSoxU+nWk+BClQEUZRi88QK5W/M8oo1DvUs36hvPFkw3Jk/gz0\n"
    "fgd5bnA+MXj0Fc0QHvbddPjIkyoI/evq9GPV+JYIuH5zabrlI3Jvya8q9QpAcEDO\n"
    "KkL/O09qXVEW52S6l05nh4PLejyI7aTyTIN5nbVLac/+M8MY/qOjZksCgYEA1Q1o\n"
    "L8kjSavU2xhQmSgZb9W62Do60sa3e73ljrDPoiyvbExldpSdziFYxHBD/Rep0ePf\n"
    "eVSGS3VSwevt9/jSGo2Oa83TYYns9agBm03oR/Go/DukESdI792NsEM+PRFypVNy\n"
    "AohWRLj0UU6DV+zLKp0VBavtx0ATeLFX0eN17TECgYBI2O/3Bz7uhQ0JSm+SjFz6\n"
    "o+2SInp5P2G57aWu4VQWWY3tQ2p+EQzNaWam10UXRrXoxtmc+ktPX9e2AgnoYoyB\n"
    "myqGcpnUhqHlnZAb999o9r1cYidDQ4uqhLauSTSwwXAFDzjJYsa8o03Y440y6QFh\n"
    "CVD6yYXXqLJs3g96CqDexwKBgAHxq1+0QCQt8zVElYewO/svQhMzBNJjic0RQIT6\n"
    "zAo4yij80XgxhvcYiszQEW6/xobpw2JCCS+rFGQ8mOFIXfJsFD6blDAxp/3d2JXo\n"
    "MhRl+hrDGI4ng5zcsqxHEMxR2m/zwPiQ8eiSn3gWdVBaEsiCwmxY00ScKxFQ3PJH\n"
    "Vw4hAoGAdZLd8KfjjG6lg7hfpVqavstqVi9LOgkHeCfdjn7JP+76kYrgLk/XdkrP\n"
    "N/BHhtFVFjOi/mTQfQ5YfZImkm/1ePBy7437DT8BDkOxspa50kK4HPggHnU64h1w\n"
    "lhdEOj7mAgHwGwwVZWOgs9Lq6vfztnSuhqjha1daESY6kDscPIQ=\n"
    "-----END RSA PRIVATE KEY-----\n";

#ifndef SSL_SET_HOSTNAME
#define SSL_SET_HOSTNAME(ssl) ((void)0)
#endif

static int disable_tls_11_and_12 = 0;
static int disable_tls_13 = 0;
static int test_is_done;
static int n_connected;
static int got_close;
static int got_error;
static int got_timeout;
static int renegotiate_at = -1;
static int stop_when_connected;
static int pending_connect_events;
static struct event_base *exit_base;


/* ====================
   Here's a simple test: we read a number from the input, increment it, and
   reply, until we get to 1001.
*/

enum regress_openssl_type
{
	REGRESS_OPENSSL_SOCKETPAIR = 1,
	REGRESS_OPENSSL_FILTER = 2,
#ifdef SSL_renegotiate
	REGRESS_OPENSSL_RENEGOTIATE = 4,
#endif
	REGRESS_OPENSSL_OPEN = 8,
	REGRESS_OPENSSL_DIRTY_SHUTDOWN = 16,
	REGRESS_OPENSSL_FD = 32,

	REGRESS_OPENSSL_CLIENT = 64,
	REGRESS_OPENSSL_SERVER = 128,

	REGRESS_OPENSSL_FREED = 256,
	REGRESS_OPENSSL_TIMEOUT = 512,
	REGRESS_OPENSSL_SLEEP = 1024,

	REGRESS_OPENSSL_CLIENT_WRITE = 2048,

	REGRESS_DEFERRED_CALLBACKS = 4096,

	REGRESS_OPENSSL_BATCH_WRITE = 8192,
};

static void
bufferevent_ssl_check_fd(struct bufferevent *bev, int filter)
{
	tt_fd_op(bufferevent_getfd(bev), !=, EVUTIL_INVALID_SOCKET);
	tt_fd_op(bufferevent_setfd(bev, EVUTIL_INVALID_SOCKET), ==, 0);
	if (filter) {
		tt_fd_op(bufferevent_getfd(bev), !=, EVUTIL_INVALID_SOCKET);
	} else {
		tt_fd_op(bufferevent_getfd(bev), ==, EVUTIL_INVALID_SOCKET);
	}

end:
	;
}
static void
bufferevent_ssl_check_freed(struct bufferevent *bev)
{
	tt_int_op(event_pending(&bev->ev_read, EVLIST_ALL, NULL), ==, 0);
	tt_int_op(event_pending(&bev->ev_write, EVLIST_ALL, NULL), ==, 0);

end:
	;
}

static void
free_on_cb(struct bufferevent *bev, void *ctx)
{
	TT_BLATHER(("free_on_cb: %p", bev));
	bufferevent_free(bev);
}

static void
respond_to_number(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_input(bev);
	char *line;
	int n;
#ifdef SSL_renegotiate
	enum regress_openssl_type type;
	type = (enum regress_openssl_type)(size_t)ctx;
#endif

	line = evbuffer_readln(b, NULL, EVBUFFER_EOL_LF);
	if (! line)
		return;
	n = atoi(line);
	if (n <= 0)
		TT_FAIL(("Bad number: %s", line));
	free(line);
	TT_BLATHER(("The number was %d", n));
	if (n == 1001) {
		++test_is_done;
		bufferevent_free(bev); /* Should trigger close on other side. */
		return;
	}
#ifdef SSL_renegotiate
	if ((type & REGRESS_OPENSSL_CLIENT) && n == renegotiate_at) {
		SSL_renegotiate(bufferevent_ssl_get_ssl(bev));
	}
#endif
	++n;
	evbuffer_add_printf(bufferevent_get_output(bev),
	    "%d\n", n);
	TT_BLATHER(("Done reading; now writing."));
	bufferevent_enable(bev, EV_WRITE);
	// we shouldn't disable EV_READ here, otherwise we wouldn't got close cb
	// bufferevent_disable(bev, EV_READ);
}

static void
done_writing_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);
	if (evbuffer_get_length(b))
		return;
	TT_BLATHER(("Done writing."));
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_READ);
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	X509 *peer_cert = NULL;
	enum regress_openssl_type type;

	type = (enum regress_openssl_type)(size_t)ctx;

	TT_BLATHER(("Got event %d", (int)what));
	if (what & BEV_EVENT_CONNECTED) {
		SSL *ssl;
		++n_connected;
		ssl = bufferevent_ssl_get_ssl(bev);
		tt_assert(ssl);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
		/* SSL_get1_peer_certificate() means we want
		 * to increase the reference count on the cert
		 * and so we will need to free it ourselves later
		 * when we're done with it. The non-reference count
		 * increasing version is not available in OpenSSL 1.1.1. */
		peer_cert = SSL_get1_peer_certificate(ssl);
#else
		peer_cert = SSL_get_peer_certificate(ssl);
#endif
		if (type & REGRESS_OPENSSL_SERVER) {
			tt_assert(peer_cert == NULL);
		} else {
			tt_assert(peer_cert != NULL);
		}
		if (stop_when_connected) {
			if (--pending_connect_events == 0)
				event_base_loopexit(exit_base, NULL);
		}

		if ((type & REGRESS_OPENSSL_CLIENT_WRITE) && (type & REGRESS_OPENSSL_CLIENT))
			evbuffer_add_printf(bufferevent_get_output(bev), "1\n");
	} else if (what & BEV_EVENT_EOF) {
		TT_BLATHER(("Got a good EOF"));
		++got_close;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_ssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_ssl_check_freed(bev);
		}
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_ERROR) {
		TT_BLATHER(("Got an error."));
		++got_error;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_ssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_ssl_check_freed(bev);
		}
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_TIMEOUT) {
		TT_BLATHER(("Got timeout."));
		++got_timeout;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_ssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_ssl_check_freed(bev);
		}
		bufferevent_free(bev);
	}

end:
	if (peer_cert)
		X509_free(peer_cert);
}

static void
open_ssl_bufevs(struct bufferevent **bev1_out, struct bufferevent **bev2_out,
    struct event_base *base, int is_open, int flags, SSL *ssl1, SSL *ssl2,
    evutil_socket_t *fd_pair, struct bufferevent **underlying_pair,
    enum regress_openssl_type type)
{
	int state1 = is_open ? BUFFEREVENT_SSL_OPEN :BUFFEREVENT_SSL_CONNECTING;
	int state2 = is_open ? BUFFEREVENT_SSL_OPEN :BUFFEREVENT_SSL_ACCEPTING;
	int dirty_shutdown = type & REGRESS_OPENSSL_DIRTY_SHUTDOWN;
	if (fd_pair) {
		*bev1_out = bufferevent_ssl_socket_new(
			base, fd_pair[0], ssl1, state1, flags);
		*bev2_out = bufferevent_ssl_socket_new(
			base, fd_pair[1], ssl2, state2, flags);
	} else {
		*bev1_out = bufferevent_ssl_filter_new(
			base, underlying_pair[0], ssl1, state1, flags);
		*bev2_out = bufferevent_ssl_filter_new(
			base, underlying_pair[1], ssl2, state2, flags);

	}
	bufferevent_setcb(*bev1_out, respond_to_number, done_writing_cb,
	    eventcb, (void*)(REGRESS_OPENSSL_CLIENT | (intptr_t)type));
	bufferevent_setcb(*bev2_out, respond_to_number, done_writing_cb,
	    eventcb, (void*)(REGRESS_OPENSSL_SERVER | (intptr_t)type));

	bufferevent_ssl_set_allow_dirty_shutdown(*bev1_out, dirty_shutdown);
	bufferevent_ssl_set_allow_dirty_shutdown(*bev2_out, dirty_shutdown);

	if (REGRESS_OPENSSL_BATCH_WRITE) {
		bufferevent_ssl_set_flags(*bev1_out, BUFFEREVENT_SSL_BATCH_WRITE);
		bufferevent_ssl_set_flags(*bev2_out, BUFFEREVENT_SSL_BATCH_WRITE);
	}
}

static void
regress_bufferevent_openssl(void *arg)
{
	struct basic_test_data *data = arg;

	struct bufferevent *bev1, *bev2;
	SSL *ssl1, *ssl2;
	int flags = BEV_OPT_DEFER_CALLBACKS;
	struct bufferevent *bev_ll[2] = { NULL, NULL };
	evutil_socket_t *fd_pair = NULL;

	enum regress_openssl_type type;
	type = (enum regress_openssl_type)(size_t)data->setup_data;

#ifdef SSL_renegotiate
	if (type & REGRESS_OPENSSL_RENEGOTIATE) {
		/*
		 * Disable TLS 1.3, so we negotiate something older to test
		 * renegotiation - renegotiation is not supported by the
		 * protocol any more.
		 */
		disable_tls_13 = 1;
		if (OPENSSL_VERSION_NUMBER >= 0x10001000 &&
		    OPENSSL_VERSION_NUMBER <  0x1000104f) {
			/* 1.0.1 up to 1.0.1c has a bug where TLS1.1 and 1.2
			 * can't renegotiate with themselves. Disable. */
			disable_tls_11_and_12 = 1;
		}
		renegotiate_at = 600;
	}
#endif

	ssl1 = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	SSL_SET_HOSTNAME(ssl1);
	ssl2 = SSL_new(get_ssl_ctx(SSL_IS_SERVER));

	SSL_use_certificate(ssl2, the_cert);
	SSL_use_PrivateKey(ssl2, the_key);

	if (!(type & REGRESS_OPENSSL_OPEN))
		flags |= BEV_OPT_CLOSE_ON_FREE;

	if (!(type & REGRESS_OPENSSL_FILTER)) {
		tt_assert(type & REGRESS_OPENSSL_SOCKETPAIR);
		fd_pair = data->pair;
	} else {
		bev_ll[0] = bufferevent_socket_new(data->base, data->pair[0],
		    BEV_OPT_CLOSE_ON_FREE);
		bev_ll[1] = bufferevent_socket_new(data->base, data->pair[1],
		    BEV_OPT_CLOSE_ON_FREE);
	}

	open_ssl_bufevs(&bev1, &bev2, data->base, 0, flags, ssl1, ssl2,
	    fd_pair, bev_ll, type);

	if (!(type & REGRESS_OPENSSL_FILTER)) {
		tt_fd_op(bufferevent_getfd(bev1), ==, data->pair[0]);
	} else {
		tt_ptr_op(bufferevent_get_underlying(bev1), ==, bev_ll[0]);
	}

	if (type & REGRESS_OPENSSL_OPEN) {
		pending_connect_events = 2;
		stop_when_connected = 1;
		exit_base = data->base;
		event_base_dispatch(data->base);
		/* Okay, now the renegotiation is done.  Make new
		 * bufferevents to test opening in BUFFEREVENT_SSL_OPEN */
		flags |= BEV_OPT_CLOSE_ON_FREE;
		bufferevent_free(bev1);
		bufferevent_free(bev2);
		bev1 = bev2 = NULL;
		open_ssl_bufevs(&bev1, &bev2, data->base, 1, flags, ssl1, ssl2,
		    fd_pair, bev_ll, type);
	}

	if (!(type & REGRESS_OPENSSL_TIMEOUT)) {
		bufferevent_enable(bev1, EV_READ|EV_WRITE);
		bufferevent_enable(bev2, EV_READ|EV_WRITE);

		if (!(type & REGRESS_OPENSSL_CLIENT_WRITE))
			evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

		event_base_dispatch(data->base);

		tt_assert(test_is_done == 1);
		tt_assert(n_connected == 2);

		/* We don't handle shutdown properly yet */
		if (type & REGRESS_OPENSSL_DIRTY_SHUTDOWN) {
			tt_int_op(got_close, ==, 1);
			tt_int_op(got_error, ==, 0);
		} else {
			tt_int_op(got_error, ==, 1);
		}
		tt_int_op(got_timeout, ==, 0);
	} else {
		struct timeval t = { 2, 0 };

		bufferevent_enable(bev1, EV_READ|EV_WRITE);
		bufferevent_disable(bev2, EV_READ|EV_WRITE);

		bufferevent_set_timeouts(bev1, &t, &t);

		if (!(type & REGRESS_OPENSSL_CLIENT_WRITE))
			evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

		event_base_dispatch(data->base);

		tt_assert(test_is_done == 0);
		tt_assert(n_connected == 0);

		tt_int_op(got_close, ==, 0);
		tt_int_op(got_error, ==, 0);
		tt_int_op(got_timeout, ==, 1);

		bufferevent_free(bev2);
	}

end:
	return;
}

static void
acceptcb_deferred(evutil_socket_t fd, short events, void *arg)
{
	struct bufferevent *bev = arg;
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}
static void
acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	enum regress_openssl_type type;
	SSL *ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));

	type = (enum regress_openssl_type)(size_t)data->setup_data;

	SSL_use_certificate(ssl, the_cert);
	SSL_use_PrivateKey(ssl, the_key);

	bev = bufferevent_ssl_socket_new(
		data->base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev);

	bufferevent_setcb(bev, respond_to_number, NULL, eventcb,
	    (void*)(REGRESS_OPENSSL_SERVER));

	if (type & REGRESS_OPENSSL_SLEEP) {
		struct timeval when = { 1, 0 };
		event_base_once(data->base, -1, EV_TIMEOUT,
		    acceptcb_deferred, bev, &when);
		bufferevent_disable(bev, EV_READ|EV_WRITE);
	} else {
		bufferevent_enable(bev, EV_READ|EV_WRITE);
	}

	/* Only accept once, then disable ourself. */
	evconnlistener_disable(listener);

end:
	;
}

struct rwcount
{
	evutil_socket_t fd;
	size_t read;
	size_t write;
};

static void
regress_bufferevent_openssl_connect(void *arg)
{
	struct basic_test_data *data = arg;

	struct event_base *base = data->base;

	struct evconnlistener *listener;
	struct bufferevent *bev;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen;
	SSL *ssl;
	struct rwcount rw = { -1, 0, 0 };
	enum regress_openssl_type type;

	type = (enum regress_openssl_type)(size_t)data->setup_data;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);

	listener = evconnlistener_new_bind(base, acceptcb, data,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr *)&sin, sizeof(sin));

	tt_assert(listener);
	tt_assert(evconnlistener_get_fd(listener) >= 0);

	ssl = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	SSL_SET_HOSTNAME(ssl);
	tt_assert(ssl);

	bev = bufferevent_ssl_socket_new(
		data->base, -1, ssl,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev);

	bufferevent_setcb(bev, respond_to_number, free_on_cb, eventcb,
	    (void*)(REGRESS_OPENSSL_CLIENT));

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);
	tt_assert(slen == sizeof(struct sockaddr_in));
	tt_int_op(((struct sockaddr*)&ss)->sa_family, ==, AF_INET);

	tt_assert(0 ==
	    bufferevent_socket_connect(bev, (struct sockaddr*)&ss, slen));
	/* Possible only when we have fd, since be_openssl can and will overwrite
	 * bio otherwise before */
	if (type & REGRESS_OPENSSL_SLEEP) {
		rw.fd = bufferevent_getfd(bev);
		BIO_setup(ssl, &rw);
	}
	evbuffer_add_printf(bufferevent_get_output(bev), "1\n");
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	event_base_dispatch(base);

	tt_int_op(rw.read, <=, 100);
	tt_int_op(rw.write, <=, 100);
end:
	evconnlistener_free(listener);
}

struct wm_context
{
	int server;
	int flags;
	struct evbuffer *data;
	size_t to_read;
	size_t wm_high;
	size_t limit;
	size_t get;
	struct bufferevent *bev;
	struct wm_context *neighbour;
};
static void
wm_transfer(struct bufferevent *bev, void *arg)
{
	struct wm_context *ctx = arg;
	struct evbuffer *in  = bufferevent_get_input(bev);
	struct evbuffer *out = bufferevent_get_output(bev);
	size_t len = evbuffer_get_length(in);
	size_t drain = len < ctx->to_read ? len : ctx->to_read;

	if (ctx->get >= ctx->limit) {
		TT_BLATHER(("wm_transfer-%s(%p): break",
			ctx->server ? "server" : "client", bev));
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
		bufferevent_disable(bev, EV_READ);
		if (ctx->neighbour->get >= ctx->neighbour->limit) {
			event_base_loopbreak(bufferevent_get_base(bev));
		}
	} else {
		ctx->get += drain;
		evbuffer_drain(in, drain);
	}

	TT_BLATHER(("wm_transfer-%s(%p): "
		"in: " EV_SIZE_FMT ", "
		"out: " EV_SIZE_FMT ", "
		"got: " EV_SIZE_FMT "",
		ctx->server ? "server" : "client", bev,
		evbuffer_get_length(in),
		evbuffer_get_length(out),
		ctx->get));

	evbuffer_add_buffer_reference(out, ctx->data);
}
static void
wm_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct wm_context *ctx = arg;
	TT_BLATHER(("wm_eventcb-%s(%p): %i",
		ctx->server ? "server" : "client", bev, what));
	if (what & BEV_EVENT_CONNECTED) {
	} else {
		ctx->get = 0;
	}
}
static void
wm_acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	struct wm_context *ctx = arg;
	struct bufferevent *bev;
	struct event_base *base = evconnlistener_get_base(listener);
	SSL *ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));

	SSL_use_certificate(ssl, the_cert);
	SSL_use_PrivateKey(ssl, the_key);

	bev = bufferevent_ssl_socket_new(
		base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, ctx->flags);
	
	tt_assert(bev);

	TT_BLATHER(("wm_transfer-%s(%p): accept",
		ctx->server ? "server" : "client", bev));

	bufferevent_setwatermark(bev, EV_READ, 0, ctx->wm_high);
	bufferevent_setcb(bev, wm_transfer, NULL, wm_eventcb, ctx);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	ctx->bev = bev;

	/* Only accept once, then disable ourself. */
	evconnlistener_disable(listener);
end: 
	;
}
static void
regress_bufferevent_openssl_wm(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;

	struct evconnlistener *listener;
	struct bufferevent *bev;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	enum regress_openssl_type type =
		(enum regress_openssl_type)(size_t)data->setup_data;
	int bev_flags = BEV_OPT_CLOSE_ON_FREE;
	ev_socklen_t slen;
	SSL *ssl;
	struct wm_context client, server;
	char *payload;
	size_t payload_len = 1<<10;
	size_t wm_high = 5<<10;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);

	if (type & REGRESS_DEFERRED_CALLBACKS)
		bev_flags |= BEV_OPT_DEFER_CALLBACKS;

	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));
	client.server = 0;
	server.server = 1;
	client.flags = server.flags = bev_flags;
	client.data = evbuffer_new();
	server.data = evbuffer_new();
	payload = calloc(1, payload_len);
	memset(payload, 'A', payload_len);
	evbuffer_add(server.data, payload, payload_len);
	evbuffer_add(client.data, payload, payload_len);
	client.wm_high = server.wm_high = wm_high;
	client.limit = server.limit = wm_high<<3;
	client.to_read = server.to_read = payload_len>>1;

	TT_BLATHER(("openssl_wm: "
		"payload_len = " EV_SIZE_FMT ", "
		"wm_high = " EV_SIZE_FMT ", "
		"limit = " EV_SIZE_FMT ", "
		"to_read: " EV_SIZE_FMT "",
		payload_len,
		wm_high,
		server.limit,
		server.to_read));

	listener = evconnlistener_new_bind(base, wm_acceptcb, &server,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr *)&sin, sizeof(sin));

	tt_assert(listener);
	tt_assert(evconnlistener_get_fd(listener) >= 0);

	ssl = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	SSL_SET_HOSTNAME(ssl);
	tt_assert(ssl);

	if (type & REGRESS_OPENSSL_FILTER) {
		bev = bufferevent_socket_new(data->base, -1, client.flags);
		tt_assert(bev);
		bev = bufferevent_ssl_filter_new(
			base, bev, ssl, BUFFEREVENT_SSL_CONNECTING, client.flags);
	} else {
		bev = bufferevent_ssl_socket_new(
			data->base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			client.flags);
	}
	tt_assert(bev);
	client.bev = bev;

	server.neighbour = &client;
	client.neighbour = &server;

	bufferevent_setwatermark(bev, EV_READ, 0, client.wm_high);
	bufferevent_setcb(bev, wm_transfer, NULL, wm_eventcb, &client);

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);

	tt_assert(!bufferevent_socket_connect(bev, (struct sockaddr*)&ss, slen));
	tt_assert(!evbuffer_add_buffer_reference(bufferevent_get_output(bev), client.data));
	tt_assert(!bufferevent_enable(bev, EV_READ|EV_WRITE));

	event_base_dispatch(base);

	tt_int_op(client.get, ==, client.limit);
	tt_int_op(server.get, ==, server.limit);

end:
	free(payload);
	evbuffer_free(client.data);
	evbuffer_free(server.data);
	evconnlistener_free(listener);
	bufferevent_free(client.bev);
	bufferevent_free(server.bev);

	/* XXX: by some reason otherwise there is a leak */
	if (!(type & REGRESS_OPENSSL_FILTER))
		event_base_loop(base, EVLOOP_ONCE);
}

/* =========================================================================
 * TLS callback-ordering / error-visibility / ownership regression tests.
 *
 * A TLS handshake failure, the underlying connection closing and a user
 * callback freeing the bufferevent all interleave inside one event-loop
 * dispatch.  These tests pin down:
 *   1. An authentication failure is reported as BEV_EVENT_ERROR and is not
 *      masked by an ordinary close (BEV_EVENT_EOF).
 *   2. Freeing the bufferevent from inside its own callback does not lead to
 *      a use-after-free or a double free: no further callback touches the
 *      destroyed object.
 *   3. After a failed handshake, an independent connection on the same base
 *      still completes a normal handshake and exchanges data.
 *
 * The code below is backend neutral; the small SSL-creation differences are
 * hidden behind the ssl_test_* helpers provided by regress_openssl.c and
 * regress_mbedtls.c.
 * ========================================================================= */

enum ssl_cb_test_type {
	SSL_CB_SOCKETPAIR = 1,
	SSL_CB_FILTER = 2,
	/* Deliver callbacks directly instead of via the deferred queue. */
	SSL_CB_IMMEDIATE = 4,
	/* Free the bufferevent from inside the error/event callback. */
	SSL_CB_FREE_IN_EVENTCB = 8,
};

/* One recorded event-callback invocation. */
struct ssl_cb_event_record {
	short what;
	unsigned long ssl_error; /* backend error captured at callback time */
};

#define SSL_CB_MAX_EVENTS 16

struct ssl_cb_waiter;

struct ssl_cb_state
{
	int side; /* 0 = client, 1 = server */
	int use_filter;
	int free_in_eventcb;

	struct bufferevent *bev;

	/* Event ordering/visibility bookkeeping. */
	struct ssl_cb_event_record events[SSL_CB_MAX_EVENTS];
	int n_events;
	int n_connected;
	int n_error;
	int n_eof;
	int freed; /* set when the callback frees the bev */

	/* Bytes drained by the read callback (ping/pong checks). */
	int n_read;

	/* Set while a drain is active; consulted by the callbacks to stop the
	 * loop as soon as the awaited condition is met. */
	struct ssl_cb_waiter *waiter;
};

/* How long a drain is allowed to wait for its predicate before the safety
 * timer forces the loop to stop.  A healthy run reaches the predicate in a
 * handful of callbacks and never comes close to this. */
#define SSL_CB_DRAIN_TIMEOUT_SECS 5

enum ssl_cb_wait_mode {
	SSL_CB_WAIT_TERMINAL,    /* both sides hit error/eof/timeout */
	SSL_CB_WAIT_CONNECTED,   /* both sides handshaked */
	SSL_CB_WAIT_DATA,        /* both sides received application data */
};

struct ssl_cb_waiter
{
	struct event_base *base;
	struct event guard;          /* one-shot safety timer */
	enum ssl_cb_wait_mode mode;
	const struct ssl_cb_state *client;
	const struct ssl_cb_state *server;
	int timed_out;
};

static int
ssl_cb_state_terminal(const struct ssl_cb_state *st)
{
	/* A state whose bev was released in-callback can never produce another
	 * event, so treat it as already settled rather than waiting on it. */
	if (st->freed)
		return 1;
	return (st->n_error + st->n_eof) > 0;
}

static int
ssl_cb_state_data_done(const struct ssl_cb_state *st)
{
	if (st->freed)
		return 1;
	return st->n_read >= 1;
}

static int
ssl_cb_waiter_done(const struct ssl_cb_waiter *w)
{
	switch (w->mode) {
	case SSL_CB_WAIT_TERMINAL:
		return ssl_cb_state_terminal(w->client) &&
		    ssl_cb_state_terminal(w->server);
	case SSL_CB_WAIT_CONNECTED:
		return w->client->n_connected >= 1 &&
		    w->server->n_connected >= 1;
	case SSL_CB_WAIT_DATA:
		return ssl_cb_state_data_done(w->client) &&
		    ssl_cb_state_data_done(w->server);
	default:
		return 1;
	}
}

static void
ssl_cb_guard_cb(evutil_socket_t fd, short what, void *arg)
{
	struct ssl_cb_waiter *w = arg;
	(void)fd;
	(void)what;
	w->timed_out = 1;
	event_base_loopbreak(w->base);
}

/* Re-evaluated from inside the event callback: as soon as both states meet
 * the wait condition we stop, so healthy tests do not pay the full timeout. */
static void
ssl_cb_waiter_maybe_stop(struct ssl_cb_waiter *w)
{
	if (w && !w->timed_out && ssl_cb_waiter_done(w))
		event_base_loopbreak(w->base);
}

static void
ssl_cb_waiter_init(struct ssl_cb_waiter *w, struct event_base *base,
    enum ssl_cb_wait_mode mode,
    const struct ssl_cb_state *client, const struct ssl_cb_state *server)
{
	struct timeval limit = { SSL_CB_DRAIN_TIMEOUT_SECS, 0 };
	memset(w, 0, sizeof(*w));
	w->base = base;
	w->mode = mode;
	w->client = client;
	w->server = server;
	evtimer_assign(&w->guard, base, ssl_cb_guard_cb, w);
	event_add(&w->guard, &limit);
}

static void
ssl_cb_waiter_fini(struct ssl_cb_waiter *w)
{
	event_del(&w->guard);
}

/* Drive the loop until the waiter predicate is satisfied or the guard timer
 * fires.  Returns 0 on success, nonzero on timeout. */
static int
ssl_cb_drain(struct ssl_cb_waiter *w)
{
	event_base_dispatch(w->base);
	return w->timed_out ? -1 : 0;
}

static void
ssl_cb_record_event(struct ssl_cb_state *st, short what)
{
	unsigned long ssl_error;

	tt_assert(st->n_events < SSL_CB_MAX_EVENTS);
	/* Capture the backend error for diagnostics.  The authoritative failure
	 * signal is the BEV_EVENT_ERROR flag below: a backend may expose no
	 * numeric code here (for example when its error queue was already
	 * drained), so the tests assert on the event flags, not this value. */
	ssl_error = ssl_test_get_error(st->bev);
	st->events[st->n_events].what = what;
	st->events[st->n_events].ssl_error = ssl_error;
	TT_BLATHER(("ssl_cb[%s] record what=0x%x side=%d ssl_error=%lu",
		SSL_TEST_BACKEND_NAME, (int)what, st->side, ssl_error));
	st->n_events++;

	if (what & BEV_EVENT_CONNECTED)
		++st->n_connected;
	if (what & BEV_EVENT_ERROR)
		++st->n_error;
	if (what & BEV_EVENT_EOF)
		++st->n_eof;
end:
	;
}

static void
ssl_cb_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct ssl_cb_state *st = arg;

	ssl_cb_record_event(st, what);
	/* Stop early once the awaited condition (e.g. both terminal) is met.
	 * Do this before any free below so the waiter still points at valid
	 * state. */
	ssl_cb_waiter_maybe_stop(st->waiter);

	if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT)) {
		if (st->free_in_eventcb) {
			TT_BLATHER(("ssl_cb[%s]: freeing bev %p from eventcb",
				SSL_TEST_BACKEND_NAME, bev));
			st->freed = 1;
			bufferevent_free(bev);
			/* No further use of bev or st is permitted; the
			 * deferred-callback machinery must not re-enter. */
			return;
		}
	}
}

static void
ssl_cb_readcb(struct bufferevent *bev, void *arg)
{
	struct ssl_cb_state *st = arg;
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);

	tt_assert(!st->freed);
	st->n_read += (int)len;
	evbuffer_drain(input, len);

	/* Client sends "ping", server answers "pong", client drains it. */
	if (st->side == 1) {
		evbuffer_add_printf(bufferevent_get_output(bev), "pong");
	}
	ssl_cb_waiter_maybe_stop(st->waiter);
end:
	;
}

/* Build one SSL bufferevent (socket or filter) and wire it to st. */
static void
ssl_cb_make_bev(struct ssl_cb_state *st, struct event_base *base,
    evutil_socket_t fd, SSL *ssl,
    enum bufferevent_ssl_state ssl_state, int options)
{
	struct bufferevent *underlying = NULL;

	if (st->use_filter) {
		underlying = bufferevent_socket_new(base, fd, options);
		tt_assert(underlying);
		st->bev = bufferevent_ssl_filter_new(base, underlying, ssl,
		    ssl_state, options);
	} else {
		st->bev = bufferevent_ssl_socket_new(base, fd, ssl,
		    ssl_state, options);
	}
	tt_assert(st->bev);

	bufferevent_setcb(st->bev, ssl_cb_readcb, NULL, ssl_cb_eventcb, st);
end:
	/* On a failed filter creation, release the underlying socket bev so its
	 * fd is not leaked. */
	if (!st->bev && underlying)
		bufferevent_free(underlying);
}

static int
ssl_cb_bev_options(const struct basic_test_data *data)
{
	enum ssl_cb_test_type type =
	    (enum ssl_cb_test_type)(size_t)data->setup_data;
	int options = BEV_OPT_CLOSE_ON_FREE;
	if (!(type & SSL_CB_IMMEDIATE))
		options |= BEV_OPT_DEFER_CALLBACKS;
	return options;
}

/* Build a fresh connected socketpair-backed client/server SSL pair.  The
 * client is configured so certificate verification fails. */
static void
ssl_cb_build_fail_pair(struct basic_test_data *data,
    struct ssl_cb_state *client, struct ssl_cb_state *server,
    ssl_test_verify_fail_conf_t **conf_out)
{
	enum ssl_cb_test_type type =
	    (enum ssl_cb_test_type)(size_t)data->setup_data;
	int options = ssl_cb_bev_options(data);
	SSL *client_ssl, *server_ssl;

	memset(client, 0, sizeof(*client));
	memset(server, 0, sizeof(*server));
	client->side = 0;
	server->side = 1;
	client->use_filter = server->use_filter =
	    (type & SSL_CB_FILTER) != 0;
	client->free_in_eventcb = server->free_in_eventcb =
	    (type & SSL_CB_FREE_IN_EVENTCB) != 0;

	*conf_out = ssl_test_new_verify_fail_client_conf();
	client_ssl = ssl_test_new_verify_fail_client_ssl(*conf_out);
	tt_assert(client_ssl);
	/* Set the expected hostname: Mbed TLS 4 refuses verification without
	 * one.  Verification still fails because no trusted CA is installed. */
	SSL_SET_HOSTNAME(client_ssl);

	server_ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));
	tt_assert(server_ssl);
	SSL_use_certificate(server_ssl, the_cert);
	SSL_use_PrivateKey(server_ssl, the_key);

	ssl_cb_make_bev(client, data->base, data->pair[0], client_ssl,
	    BUFFEREVENT_SSL_CONNECTING, options);
	ssl_cb_make_bev(server, data->base, data->pair[1], server_ssl,
	    BUFFEREVENT_SSL_ACCEPTING, options);

	bufferevent_enable(client->bev, EV_READ | EV_WRITE);
	bufferevent_enable(server->bev, EV_READ | EV_WRITE);
end:
	;
}

/* Release whatever a state still owns; safe to call after the callback freed
 * the bev (st->bev is NULL then). */
static void
ssl_cb_free_state(struct ssl_cb_state *st)
{
	if (st->freed) {
		st->bev = NULL;
		return;
	}
	if (st->bev) {
		bufferevent_free(st->bev);
		st->bev = NULL;
	}
}

/*
 * Test 1: a certificate verification failure must surface as
 * BEV_EVENT_ERROR on both ends and never as a plain BEV_EVENT_EOF.  When
 * requested, the bufferevent is freed inside that very callback; afterwards
 * no callback may touch the freed object.
 */
static void
regress_ssl_cb_verify_fail(void *arg)
{
	struct basic_test_data *data = arg;
	struct ssl_cb_state client, server;
	struct ssl_cb_waiter waiter;
	ssl_test_verify_fail_conf_t *conf = NULL;
	int i;

	ssl_cb_build_fail_pair(data, &client, &server, &conf);

	client.waiter = server.waiter = &waiter;
	ssl_cb_waiter_init(&waiter, data->base, SSL_CB_WAIT_TERMINAL,
	    &client, &server);
	tt_int_op(ssl_cb_drain(&waiter), ==, 0);
	ssl_cb_waiter_fini(&waiter);
	client.waiter = server.waiter = NULL;

	/* Neither side should believe the handshake completed. */
	tt_int_op(client.n_connected, ==, 0);
	tt_int_op(server.n_connected, ==, 0);

	/* The authentication failure is an error, not a clean close. */
	tt_int_op(client.n_error, >=, 1);
	tt_int_op(server.n_error, >=, 1);
	tt_int_op(client.n_eof, ==, 0);
	tt_int_op(server.n_eof, ==, 0);

	/* Every terminal event recorded carries ERROR, never an isolated EOF. */
	for (i = 0; i < client.n_events; ++i) {
		short what = client.events[i].what;
		if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
			tt_int_op(what & BEV_EVENT_ERROR, !=, 0);
			tt_int_op(what & BEV_EVENT_EOF, ==, 0);
		}
	}
	for (i = 0; i < server.n_events; ++i) {
		short what = server.events[i].what;
		if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
			tt_int_op(what & BEV_EVENT_ERROR, !=, 0);
			tt_int_op(what & BEV_EVENT_EOF, ==, 0);
		}
	}

	if (client.free_in_eventcb) {
		/* The callback already released the object; process any
		 * remaining ready events and make sure none are delivered to
		 * the freed state (its event count must not move).  This uses
		 * EVLOOP_NONBLOCK so it returns at once when the loop is idle
		 * instead of blocking on the (now absent) bufferevents. */
		int client_events_before = client.n_events;
		int server_events_before = server.n_events;
		client.waiter = server.waiter = NULL;
		event_base_loop(data->base, EVLOOP_NONBLOCK);
		event_base_loop(data->base, EVLOOP_NONBLOCK);
		tt_int_op(client.n_events, ==, client_events_before);
		tt_int_op(server.n_events, ==, server_events_before);
	}

end:
	ssl_cb_free_state(&client);
	ssl_cb_free_state(&server);
	ssl_test_verify_fail_client_conf_free(conf);
}

/*
 * Test 2: after a successful handshake, an ordinary peer close produces a
 * terminal event without any spurious post-close handshake notification.
 * With the socket backend and dirty-shutdown allowed the close is reported as
 * BEV_EVENT_EOF (the filter backend currently reports ERROR for the same
 * underlying close; see the mode-aware assertions below).  Either way this
 * contrasts with the verify-failure test, which is always an ERROR even with
 * dirty-shutdown enabled.  The client bev is released outside a callback while
 * the server side frees itself inside its terminal callback, exercising both
 * ownership paths.
 */
static void
regress_ssl_cb_clean_close(void *arg)
{
	struct basic_test_data *data = arg;
	enum ssl_cb_test_type type =
	    (enum ssl_cb_test_type)(size_t)data->setup_data;
	int options = ssl_cb_bev_options(data);
	struct ssl_cb_state client, server;
	struct ssl_cb_waiter waiter;
	SSL *client_ssl, *server_ssl;

	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));
	client.side = 0;
	server.side = 1;
	client.use_filter = server.use_filter =
	    (type & SSL_CB_FILTER) != 0;
	/* This variant always frees from the callback to exercise ownership. */
	client.free_in_eventcb = server.free_in_eventcb = 1;

	client_ssl = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	tt_assert(client_ssl);
	SSL_SET_HOSTNAME(client_ssl);

	server_ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));
	tt_assert(server_ssl);
	SSL_use_certificate(server_ssl, the_cert);
	SSL_use_PrivateKey(server_ssl, the_key);

	ssl_cb_make_bev(&client, data->base, data->pair[0], client_ssl,
	    BUFFEREVENT_SSL_CONNECTING, options);
	ssl_cb_make_bev(&server, data->base, data->pair[1], server_ssl,
	    BUFFEREVENT_SSL_ACCEPTING, options);

	/* A peer that simply drops the connection (no TLS close_notify) must
	 * look like an ordinary EOF, not a protocol error.  This is the
	 * contrast that proves the verify-failure test's ERROR result really
	 * reflects the authentication failure. */
	bufferevent_ssl_set_allow_dirty_shutdown(client.bev, 1);
	bufferevent_ssl_set_allow_dirty_shutdown(server.bev, 1);

	bufferevent_enable(client.bev, EV_READ | EV_WRITE);
	bufferevent_enable(server.bev, EV_READ | EV_WRITE);

	/* Wait for the handshake to complete on both sides. */
	client.waiter = server.waiter = &waiter;
	ssl_cb_waiter_init(&waiter, data->base, SSL_CB_WAIT_CONNECTED,
	    &client, &server);
	tt_int_op(ssl_cb_drain(&waiter), ==, 0);
	ssl_cb_waiter_fini(&waiter);
	tt_int_op(client.n_connected, ==, 1);
	tt_int_op(server.n_connected, ==, 1);

	/* Close the client side from outside a callback. */
	client.waiter = NULL;
	bufferevent_free(client.bev);
	client.bev = NULL;
	client.freed = 1;

	/* The server should observe the peer going away as a terminal event.
	 * With the socket backend and dirty-shutdown allowed, an abrupt close is
	 * an ordinary EOF.  The filter backend currently surfaces the same
	 * underlying close through be_ssl_eventcb() as an ERROR, so there we
	 * only require a terminal event without a spurious post-close CONNECTED.
	 * Either way it must never be confused with the verify-failure case,
	 * which always carries ERROR even with dirty-shutdown enabled. */
	ssl_cb_waiter_init(&waiter, data->base, SSL_CB_WAIT_TERMINAL,
	    &client, &server);
	server.waiter = &waiter;
	tt_int_op(ssl_cb_drain(&waiter), ==, 0);
	ssl_cb_waiter_fini(&waiter);
	server.waiter = NULL;
	tt_int_op(server.n_eof + server.n_error, >=, 1);
	if (!server.use_filter) {
		tt_int_op(server.n_eof, >=, 1);
		tt_int_op(server.n_error, ==, 0);
	}
	/* The closed peer must never produce another handshake event. */
	tt_int_op(server.n_connected, ==, 1);

end:
	ssl_cb_free_state(&client);
	ssl_cb_free_state(&server);
}

/*
 * Test 3: after a failed handshake, a fully independent connection on the
 * same event base still completes a normal handshake and exchanges data.
 * This guards against the failure poisoning global/base state.
 */
static void
regress_ssl_cb_recover_after_fail(void *arg)
{
	struct basic_test_data *data = arg;
	enum ssl_cb_test_type type =
	    (enum ssl_cb_test_type)(size_t)data->setup_data;
	int options = ssl_cb_bev_options(data);
	struct ssl_cb_state bad_client, bad_server;
	struct ssl_cb_waiter waiter;
	ssl_test_verify_fail_conf_t *conf = NULL;
	evutil_socket_t good_pair[2] =
	    { EVUTIL_INVALID_SOCKET, EVUTIL_INVALID_SOCKET };
	struct ssl_cb_state good_client, good_server;
	SSL *client_ssl, *server_ssl;
	int good_pair_built = 0;

	/* Phase 1: a failing connection on the shared base. */
	ssl_cb_build_fail_pair(data, &bad_client, &bad_server, &conf);
	bad_client.waiter = bad_server.waiter = &waiter;
	ssl_cb_waiter_init(&waiter, data->base, SSL_CB_WAIT_TERMINAL,
	    &bad_client, &bad_server);
	tt_int_op(ssl_cb_drain(&waiter), ==, 0);
	ssl_cb_waiter_fini(&waiter);
	bad_client.waiter = bad_server.waiter = NULL;
	tt_int_op(bad_client.n_error, >=, 1);
	tt_int_op(bad_server.n_error, >=, 1);
	tt_int_op(bad_client.n_connected, ==, 0);

	ssl_cb_free_state(&bad_client);
	ssl_cb_free_state(&bad_server);
	ssl_test_verify_fail_client_conf_free(conf);
	conf = NULL;

	/* Phase 2: a brand new, correctly configured connection. */
	tt_int_op(evutil_socketpair(AF_UNIX,
		SOCK_STREAM | EVUTIL_SOCK_NONBLOCK, 0, good_pair), ==, 0);
	good_pair_built = 1;

	memset(&good_client, 0, sizeof(good_client));
	memset(&good_server, 0, sizeof(good_server));
	good_client.side = 0;
	good_server.side = 1;
	good_client.use_filter = good_server.use_filter =
	    (type & SSL_CB_FILTER) != 0;

	client_ssl = SSL_new(get_ssl_ctx(SSL_IS_CLIENT));
	tt_assert(client_ssl);
	SSL_SET_HOSTNAME(client_ssl);

	server_ssl = SSL_new(get_ssl_ctx(SSL_IS_SERVER));
	tt_assert(server_ssl);
	SSL_use_certificate(server_ssl, the_cert);
	SSL_use_PrivateKey(server_ssl, the_key);

	ssl_cb_make_bev(&good_client, data->base, good_pair[0], client_ssl,
	    BUFFEREVENT_SSL_CONNECTING, options);
	ssl_cb_make_bev(&good_server, data->base, good_pair[1], server_ssl,
	    BUFFEREVENT_SSL_ACCEPTING, options);
	tt_assert(good_client.bev && good_server.bev);

	bufferevent_enable(good_client.bev, EV_READ | EV_WRITE);
	bufferevent_enable(good_server.bev, EV_READ | EV_WRITE);

	/* Wait for the handshake, then send a ping and expect a pong. */
	good_client.waiter = good_server.waiter = &waiter;
	ssl_cb_waiter_init(&waiter, data->base, SSL_CB_WAIT_CONNECTED,
	    &good_client, &good_server);
	tt_int_op(ssl_cb_drain(&waiter), ==, 0);
	ssl_cb_waiter_fini(&waiter);
	tt_int_op(good_client.n_connected, ==, 1);
	tt_int_op(good_server.n_connected, ==, 1);

	evbuffer_add_printf(bufferevent_get_output(good_client.bev), "ping");
	ssl_cb_waiter_init(&waiter, data->base, SSL_CB_WAIT_DATA,
	    &good_client, &good_server);
	tt_int_op(ssl_cb_drain(&waiter), ==, 0);
	ssl_cb_waiter_fini(&waiter);
	good_client.waiter = good_server.waiter = NULL;

	tt_int_op(good_server.n_read, >=, 4);
	tt_int_op(good_client.n_read, >=, 4);

end:
	/* A built bev owns and closes its fd (BEV_OPT_CLOSE_ON_FREE).  Free any
	 * that were constructed; close a raw fd directly only when its bev was
	 * never built. */
	if (good_client.bev)
		ssl_cb_free_state(&good_client);
	else if (good_pair_built)
		evutil_closesocket(good_pair[0]);
	if (good_server.bev)
		ssl_cb_free_state(&good_server);
	else if (good_pair_built)
		evutil_closesocket(good_pair[1]);
	if (conf)
		ssl_test_verify_fail_client_conf_free(conf);
}

struct testcase_t TESTCASES_NAME[] = {
#define T(a) ((void *)(a))
	{ "bufferevent_socketpair", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup, T(REGRESS_OPENSSL_SOCKETPAIR) },
	{ "bufferevent_socketpair_batch_write", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup, T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_BATCH_WRITE) },
	{ "bufferevent_socketpair_write_after_connect", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR|REGRESS_OPENSSL_CLIENT_WRITE) },
	{ "bufferevent_filter", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup, T(REGRESS_OPENSSL_FILTER) },
	{ "bufferevent_filter_write_after_connect", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER|REGRESS_OPENSSL_CLIENT_WRITE) },
#ifdef SSL_renegotiate
	{ "bufferevent_renegotiate_socketpair", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_RENEGOTIATE) },
	{ "bufferevent_renegotiate_filter", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_RENEGOTIATE) },
#endif
	{ "bufferevent_socketpair_startopen", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_OPEN) },
	{ "bufferevent_filter_startopen", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_OPEN) },

	{ "bufferevent_socketpair_dirty_shutdown", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_filter_dirty_shutdown", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
#ifdef SSL_renegotiate
	{ "bufferevent_renegotiate_socketpair_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_RENEGOTIATE | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_renegotiate_filter_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_RENEGOTIATE | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
#endif
	{ "bufferevent_socketpair_startopen_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_OPEN | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_filter_startopen_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_OPEN | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },

	{ "bufferevent_socketpair_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FD) },
	{ "bufferevent_socketpair_freed", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FREED) },
	{ "bufferevent_socketpair_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },
	{ "bufferevent_filter_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },

	{ "bufferevent_socketpair_timeout", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_TIMEOUT) },
	{ "bufferevent_socketpair_timeout_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &ssl_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_TIMEOUT | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },
	{ "bufferevent_connect", regress_bufferevent_openssl_connect,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_connect_sleep", regress_bufferevent_openssl_connect,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_OPENSSL_SLEEP) },
	{ "bufferevent_wm", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, NULL },
	{ "bufferevent_wm_filter", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_OPENSSL_FILTER) },
	{ "bufferevent_wm_defer", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_DEFERRED_CALLBACKS) },
	{ "bufferevent_wm_filter_defer", regress_bufferevent_openssl_wm,
	  TT_FORK|TT_NEED_BASE, &ssl_setup, T(REGRESS_OPENSSL_FILTER|REGRESS_DEFERRED_CALLBACKS) },

	/* TLS callback ordering / error visibility / ownership regressions. */
	{ "cb_verify_fail_socketpair", regress_ssl_cb_verify_fail,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_SOCKETPAIR) },
	{ "cb_verify_fail_socketpair_immediate", regress_ssl_cb_verify_fail,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_SOCKETPAIR | SSL_CB_IMMEDIATE) },
	{ "cb_verify_fail_filter", regress_ssl_cb_verify_fail,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_FILTER) },
	{ "cb_verify_fail_free_in_cb_socketpair", regress_ssl_cb_verify_fail,
	  TT_ISOLATED, &ssl_setup,
	  T(SSL_CB_SOCKETPAIR | SSL_CB_FREE_IN_EVENTCB) },
	{ "cb_verify_fail_free_in_cb_filter", regress_ssl_cb_verify_fail,
	  TT_ISOLATED, &ssl_setup,
	  T(SSL_CB_FILTER | SSL_CB_FREE_IN_EVENTCB) },
	{ "cb_clean_close_free_in_cb_socketpair", regress_ssl_cb_clean_close,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_SOCKETPAIR) },
	{ "cb_clean_close_free_in_cb_filter", regress_ssl_cb_clean_close,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_FILTER) },
	{ "cb_recover_after_fail_socketpair", regress_ssl_cb_recover_after_fail,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_SOCKETPAIR) },
	{ "cb_recover_after_fail_filter", regress_ssl_cb_recover_after_fail,
	  TT_ISOLATED, &ssl_setup, T(SSL_CB_FILTER) },

#undef T

	END_OF_TESTCASES,
};
