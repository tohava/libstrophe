#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h> // TODO: I am assuming openssl here, but what if the other lib is used. this breaks Windows compatibility?

#include "common.h"

#define MAX_BEV_READ_WATERMARK 16384

static void _handle_connect(evutil_socket_t fd, short what, void *arg);
static void _handle_read(struct bufferevent *bev, void *arg);
static void _handle_error(struct bufferevent *bev, short error, void *arg);

struct xmppevent {
    xmpp_conn_t *conn;
    struct bufferevent *bev;
    struct bufferevent *bev_ssl;
    struct event_base *base;
};

struct _tls { // TODO: I am assuming openssl here, but what if the other lib is used. this breaks Windows compatibility?
    xmpp_ctx_t *ctx;
    sock_t sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int lasterror;
};

void conn_ev_send_raw(xev_t * const xev,
                      const char * const data, const size_t len)
{
    // THESE SHOULD BE DEFINED HERE INSTEAD
    void client_xmpp_buffer_read_cb(struct bufferevent *bev, void *arg);
    void client_xmpp_buffer_error_cb(struct bufferevent *bev, short error, void *arg);

#define conn xev->conn
#define tls conn->tls
#define ssl tls->ssl
#define bev_ssl xev->bev_ssl
    if (conn->tls && !bev_ssl) {
        bev_ssl = bufferevent_openssl_filter_new(xev->base, xev->bev, ssl, BUFFEREVENT_SSL_OPEN, 0);
        bufferevent_setcb(bev_ssl, _handle_read, NULL, _handle_error, xev);
        bufferevent_setwatermark(bev_ssl, EV_READ, 0, 4096);
        bufferevent_enable(bev_ssl, EV_READ|EV_WRITE);
        
        if (!bev_ssl)
            abort(); // TODO: better fail code here
    }
        
    if (bufferevent_write(conn->tls ? bev_ssl : xev->bev, data, len) != 0)
        abort(); // TODO: better fail code here
#undef bev_ssl
#undef ssl
#undef tls
#undef conn
}

xmpp_conn_t *xmpp_conn_ev_new(xmpp_ctx_t *ctx, struct event_base *base)
{
#define conn xev->conn
    xev_t *xev = malloc(sizeof(xev_t));

    xev->base = base;
    conn = xmpp_conn_new(ctx);
    conn->xev = xev;
    
    return conn;
#undef conn
}

void conn_ev_add_connect_handler(xev_t *xev)
{
    struct timeval connect_timeout = {xev->conn->connect_timeout / 1000,
                                      xev->conn->connect_timeout % 1000};
    event_add(
      event_new(xev->base,
                xev->conn->sock,
                EV_WRITE,
                _handle_connect,
                xev),
      &connect_timeout);
}

static void _handle_connect(evutil_socket_t fd, short what, void *arg)
{
    xev_t *xev = arg;
#define conn xev->conn
#define bev xev->bev
#define base xev->base
#define ctx conn->ctx
    if ((what & EV_TIMEOUT) || sock_connect_error(conn->sock)) {
        conn_disconnect(conn);
    } else {
        char buf[1024];
        xmpp_sized_string_t str;
        bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, _handle_read, NULL, _handle_error, xev);
        bufferevent_setwatermark(bev, EV_READ, 0, MAX_BEV_READ_WATERMARK);
        bufferevent_enable(bev, EV_READ|EV_WRITE);
        conn->state = XMPP_STATE_CONNECTED;
        str = xmpp_snprintf_heap(ctx, buf, 1024, 
    			                 "<?xml version=\"1.0\"?>"
    			                 "<stream:stream to=\"%s\" "
    			                 "xml:lang=\"%s\" "
    			                 "version=\"1.0\" "
    			                 "xmlns=\"%s\" "
    			                 "xmlns:stream=\"%s\">", 
    			                 conn->domain,
    			                 conn->lang,
    			                 conn->type == XMPP_CLIENT ? XMPP_NS_CLIENT : XMPP_NS_COMPONENT,
    			                 XMPP_NS_STREAMS);
        bufferevent_write(bev, str.buf, str.len - 1);
        if (str.buf != buf)
            xmpp_free(ctx, str.buf);
    }
#undef conn
#undef bev 
#undef base
#undef ctx
}

static void _handle_read(struct bufferevent *bev, void *arg)
{
    xev_t *xev = arg;
#define conn xev->conn
#define ctx conn->ctx
    char buf[4096];
    size_t len;
    int ret;
    len = bufferevent_read(bev, buf, sizeof(buf));
    if (conn->reset_parser)
        conn_parser_reset(conn);
    ret = parser_feed(conn->parser, buf, len);
    if (!ret) {
        xmpp_debug(ctx, "xmpp", "parse error, disconnecting");
        // TODO: handle error correctly
    }
#undef ctx
#undef conn
}

static void _handle_error(struct bufferevent *bev, short error, void *arg)
{
    // TODO: NOT IMPLEMENTED
}

void conn_ev_xev_free(xmpp_conn_t * const conn)
{
#define xev conn->xev
    bufferevent_free(xev->bev_ssl);
    bufferevent_free(xev->bev);
    free(xev);
    xev = NULL;
#undef xev    
}
