/**
 * openngtcp2
 *
 * Copyright (C) 2018, TUTU 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions: 
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software. 
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL 
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE. 
 * 
 **/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/socket.h>

#include <openngtcp2.h>

#include <event2/event.h>

#define MAX_CLIENT (1024)
typedef struct {
    int     fd;
    QUIC    *quic;
    bool    draining;
    struct event *read_event;
    struct event *write_event;
    char addr_str[256], port_str[256];
} Client;

static int fd4, fd6;
static struct event_base *base = NULL;
static struct sockaddr_storage ss4, ss6;
static socklen_t ss4_len, ss6_len;
static Client *client_list[MAX_CLIENT];
static void usage(const char *cmd);
static void signal_cb(int sig, short what, void *arg);
static int create_socket(sa_family_t family, const char *host, const char *port);
static bool quic_ctx_set_certificate(QUIC_CTX *quic_ctx, const char *cert, const char *key);
static int use_libevent(QUIC_CTX *quic_ctx, int fd4, int fd6);
static void new_client_handler(int fd, short event, void *arg);
static void do_accept(int server_fd, QUIC_CTX *quic_ctx, QUIC_PREACCEPT *pre_data);
static Client *init_client(QUIC *quic, int fd);
static void free_client(Client *c);
static void read_handler(int fd, short event, void *arg);
static void write_handler(int fd, short event, void *arg);
static void do_handshake(Client *c, bool timeout);
static void do_read(Client *c);
static void do_disconnect(Client *c);
static void do_draining(Client *c);

int main(int argc, char *argv[]) {
    int         i, c, ret;
    char        errbuf[QUIC_ERRBUF_SIZE];
    QUIC_CTX    *quic_ctx;
    const char  *port = NULL, *cert = NULL, *key = NULL;

    opterr = 0;
    while((c = getopt(argc, argv, "p:c:k:")) != EOF) {
        switch(c) {
            case 'p':
                port = optarg;
                break;

            case 'c':
                cert = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            default:
                usage(argv[0]);
        }//end switch
    }//end while

    if(!port || !cert || !key) {
        usage(argv[0]);
    }//end if

    //open socket
    fd4 = create_socket(PF_INET, "localhost", port);
    if(fd4 < 0) {
        fprintf(stderr, "Fail to bind to [%s]:%s\n", "localhost", port);
        return 1;
    }//end if

    fd6 = create_socket(PF_INET6, "localhost", port);
    if(fd6 < 0) {
        fprintf(stderr, "Fail to bind to [%s]:%s\n", "localhost", port);
        close(fd4);
        return 1;
    }//end if

    //init QUIC_CTX
    quic_ctx = QUIC_CTX_new(errbuf);
    if(!quic_ctx) {
        fprintf(stderr, "Fail to allocating QUIC_CTX: %s\n", errbuf);
        close(fd4);
        close(fd6);
        return 1;
    }//end if

    //set cert
    if(!quic_ctx_set_certificate(quic_ctx, cert, key)) {
        fprintf(stderr, "%s\n", QUIC_CTX_get_err(quic_ctx));
        QUIC_CTX_free(quic_ctx);
        close(fd4);
        close(fd6);
        return 1;
    }//end if

    ret = use_libevent(quic_ctx, fd4, fd6);

    //shutdown all
    for(i = 0 ; i < MAX_CLIENT ; i++) {
        if(client_list[i]) {
            do_disconnect(client_list[i]);
        }//end if
    }//end for

    QUIC_CTX_free(quic_ctx);
        close(fd4);
        close(fd6);
    return ret == 0 ? 0 : 1;
}//end main


/* ===== private function ===== */
static void usage(const char *cmd) {
    fprintf(stderr, "%s [-p port] [-c certificate] [-k key of certificate]\n", cmd);
    exit(1);
}//end usage

static void signal_cb(int sig, short what, void *arg) {
    struct event_base *base;

    base = (struct event_base *)arg;
    printf("Signal %s caught\n", strsignal(sig));
    event_base_loopbreak(base);
}//end signal_cb

static int create_socket(sa_family_t family, const char *host, const char *port) {
    int         fd, ret;
    char        errbuf[QUIC_ERRBUF_SIZE];
    char        addr_str[INET_ADDRSTRLEN + INET6_ADDRSTRLEN], port_str[256];
    socklen_t   *ss_len;
    struct sockaddr_storage *ss;

    fd = QUIC_bind_fd_to_host(family, host, port, errbuf);
    if(fd < 0) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }//end if

    if(family == PF_INET) {
        ss = &ss4;
        ss_len = &ss4_len;
    }//end if
    else if(family == PF_INET6) {
        ss = &ss6;
        ss_len = &ss6_len;
    }//end if
    else {
        return fd;
    }//end else

    *ss_len = sizeof(struct sockaddr_storage);
    if(getsockname(fd, (struct sockaddr *)ss, ss_len) != 0) {
        perror("getsockname()");
        close(fd);
        return -1;
    }//end if

    //better than inet_ntop()
    ret = getnameinfo(
        (struct sockaddr *)ss, *ss_len,
        addr_str, sizeof(addr_str),
        port_str, sizeof(port_str),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if(ret != 0) {
        fprintf(stderr, "getnameinfo(): %s\n", gai_strerror(ret));
        close(fd);
        return -1;
    }//end if

    printf("Local address is [%s]:%s\n", addr_str, port_str);

    //set to non-block
    if(evutil_make_socket_nonblocking(fd) != 0) {
        fprintf(stderr, "Fail to set nonblocking\n");
        close(fd);
        return -1;
    }//end if

    return fd;
}//end create_socket

static bool quic_ctx_set_certificate(QUIC_CTX *quic_ctx, const char *cert, const char *key) {
    if(QUIC_CTX_use_certificate_file(quic_ctx, cert) != QUIC_ERR_NONE) {
        return false;
    }//end if
    if(QUIC_CTX_use_PrivateKey_file(quic_ctx, key) != QUIC_ERR_NONE) {
        return false;
    }//end if
    return QUIC_CTX_check_private_key(quic_ctx);
}//end quic_ctx_set_certificate

static int use_libevent(QUIC_CTX *quic_ctx, int fd4, int fd6) {
    int             ret = 0;
    struct event    *sigint_event = NULL, *sigterm_event = NULL, *new_client4_event = NULL, *new_client6_event = NULL;

    do {
        //init libevent
        base = event_base_new();
        if(!base) {
            fprintf(stderr, "event_base_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if

        sigint_event = evsignal_new(base, SIGINT, signal_cb, (void *)base);
        if(!sigint_event) {
            fprintf(stderr, "evsignal_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if
        event_add(sigint_event, NULL);

        sigterm_event = evsignal_new(base, SIGTERM, signal_cb, (void *)base);
        if(!sigterm_event) {
            fprintf(stderr, "evsignal_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if
        event_add(sigterm_event, NULL);

        new_client4_event = event_new(base, fd4, EV_READ|EV_PERSIST, new_client_handler, (void *)quic_ctx);
        if(!new_client4_event) {
            fprintf(stderr, "evsignal_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if
        event_add(new_client4_event, NULL);

        new_client6_event = event_new(base, fd6, EV_READ|EV_PERSIST, new_client_handler, (void *)quic_ctx);
        if(!new_client6_event) {
            fprintf(stderr, "evsignal_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if
        event_add(new_client6_event, NULL);

        printf("Going to event loop\n");
        if(event_base_dispatch(base) != 0) {
            fprintf(stderr, "event_base_dispatch(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if
    }//end do
    while(0);

    if(sigint_event) {
        event_free(sigint_event);
        sigint_event = NULL;
    }//end if
    if(sigterm_event) {
        event_free(sigterm_event);
        sigterm_event = NULL;
    }//end if
    if(new_client4_event) {
        event_free(new_client4_event);
        new_client4_event = NULL;
    }//end if
    if(new_client6_event) {
        event_free(new_client6_event);
        new_client6_event = NULL;
    }//end if
    if(base) {
        event_base_free(base);
        base = NULL;
    }//end if
    return ret;
}//end use_libevent

static void new_client_handler(int fd, short event, void *arg) {
    char            errbuf[QUIC_ERRBUF_SIZE];
    QUIC_CTX        *quic_ctx;
    quic_err_t      err;
    QUIC_PREACCEPT  pre_data;

    quic_ctx = (QUIC_CTX *)arg;
    err = QUIC_preaccept(fd, &pre_data, errbuf);
    if(err == QUIC_ERR_QUIC_WANT_READ) {
        return;
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_WRITE) {
        QUIC_send_version_negotiation(fd, &pre_data, errbuf);
        //ignore error
    }//end if
    else if(err == QUIC_ERR_NONE) {
        do_accept(fd, quic_ctx, &pre_data);
    }//end if
    else if(err != QUIC_ERR_NONE) {
        fprintf(stderr, "%s\n", errbuf);
        return;
    }//end if
}//end new_client_handler

static void do_accept(int server_fd, QUIC_CTX *quic_ctx, QUIC_PREACCEPT *pre_data) {
    int                 client_fd, ret;
    QUIC                *quic;
    char                errbuf[QUIC_ERRBUF_SIZE];
    Client              *c;
    socklen_t           addr_len, *len;
    quic_err_t          err;
    struct sockaddr_storage addr, *ss;

    //bind to address in this case is necessary
    if(server_fd == fd4) {
        ss = &ss4;
        len = &ss4_len;
    }//end if
    else if(server_fd == fd6) {
        ss = &ss6;
        len = &ss6_len;
    }//end if
    else {
        return;
    }//end else

    quic = QUIC_new_accept(quic_ctx, pre_data, errbuf);
    if(!quic) {
        fprintf(stderr, "%s\n", errbuf);
        return;
    }//end if

    //open client socket
    QUIC_get_addr_in_preaccept(&addr, &addr_len, pre_data);
    client_fd = QUIC_connect_fd_to_addr(ss, *len, &addr, addr_len, errbuf);
    if(client_fd < 0) {
        fprintf(stderr, "%s\n", errbuf);
        QUIC_free(quic);
        return;
    }//end if

    if(client_fd >= MAX_CLIENT) {
        fprintf(stderr, "Reach maximum fd can open\n");
        QUIC_free(quic);
        close(client_fd);
        return;
    }//end if

    //set fd
    err = QUIC_set_fd(quic, client_fd);
    if(err != QUIC_ERR_NONE) {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
        QUIC_free(quic);
        close(client_fd);
        return;
    }//end if

    //init client object
    c = init_client(quic, client_fd);
    if(!c) {
        QUIC_free(quic);
        close(client_fd);
        return;
    }//end if

    //better than inet_ntop()
    ret = getnameinfo(
        (struct sockaddr *)&addr, addr_len,
        c->addr_str, sizeof(c->addr_str),
        c->port_str, sizeof(c->port_str),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if(ret != 0) {
        fprintf(stderr, "getnameinfo(): %s\n", gai_strerror(ret));
        QUIC_free(quic);
        close(client_fd);
        return;
    }//end if
    else {
        printf("New client from [%s]:%s\n", c->addr_str, c->port_str);
    }//end else

    client_list[client_fd] = c;
    event_add(c->read_event, NULL);
}//end do_accept

static Client *init_client(QUIC *quic, int fd) {
    Client *c;

    c = calloc(1, sizeof(Client));
    if(!c) {
        perror("calloc()");
        return NULL;
    }//end if

    c->fd = fd;
    c->quic = quic;
    c->read_event = event_new(base, fd, EV_READ, read_handler, (void *)c);
    if(!c->read_event) {
        free_client(c);
        return NULL;
    }//end if
    c->write_event = event_new(base, fd, EV_WRITE, write_handler, (void *)c);
    if(!c->write_event) {
        free_client(c);
        return NULL;
    }//end if

    //greeting
    char data[] = "Hello!";
    QUIC_set_data_to_stream(c->quic, (u_int8_t *)data, strlen(data), NULL);

    return c;
}//end init_client

static void free_client(Client *c) {
    if(c) {
        if(c->fd >= 0) {
            close(c->fd);
        }//end if
        if(c->quic) {
            QUIC_free(c->quic);
        }//end if
        if(c->read_event) {
            event_free(c->read_event);
        }//end if
        if(c->write_event) {
            event_free(c->write_event);
        }//end if

        free(c);
    }//end if
}//end free_client

static void read_handler(int fd, short event, void *arg) {
    Client *c;

    c = (Client *)arg;
    if(!QUIC_is_init_finished(c->quic)) {
        do_handshake(c, event & EV_TIMEOUT);
    }//end if
    else {
        if(event & EV_TIMEOUT) {
            printf("Timeout!\n");
            do_disconnect(c);
        }//end if
        else {
            do_read(c);
        }//end else
    }//end else
}//end read_handler

static void write_handler(int fd, short event, void *arg) {
    Client *c;

    c = (Client *)arg;
    if(!QUIC_is_init_finished(c->quic)) {
        do_handshake(c, event & EV_TIMEOUT);
    }//end if
    else {
        QUIC_write_streams(c->quic);
    }//end else
}//end write_handler

static void do_handshake(Client *c, bool timeout) {
    quic_err_t      err;
    struct timeval  tv;
    struct timespec ts;

    if(timeout) {
        err = QUIC_do_retransmit(c->quic);
    }//end if
    else {
        err = QUIC_do_handshake(c->quic);
    }//end else

    if(err == QUIC_ERR_QUIC_WANT_READ) {
        ts = QUIC_get_retransmit_timestamp(c->quic);
        QUIC_timespec_to_timeval(&ts, &tv);
        event_add(c->read_event, &tv);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_WRITE) {
        event_add(c->write_event, NULL);
    }//end if
    else if(err == QUIC_ERR_NONE) {
        printf("Handshake is done\n");
        event_add(c->read_event, NULL);
    }//end if
    else {
        fprintf(stderr, "%s\n", QUIC_get_err(c->quic));
        do_disconnect(c);
    }//end else
}//end do_handshake

static void do_read(Client *c) {
    size_t          nread;
    u_int8_t        buf[65536];
    u_int64_t       stream_id;
    quic_err_t      err;
    struct timeval  tv;

    tv.tv_sec = 30;
    tv.tv_usec = 0;
    err = QUIC_read_stream(c->quic, buf, sizeof(buf), &nread, &stream_id);
    if(err == QUIC_ERR_QUIC_WANT_READ) {
        event_add(c->read_event, &tv);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_WRITE) {
        event_add(c->write_event, NULL);
    }//end if
    else if(err == QUIC_ERR_NONE) {
        printf("Read %zd bytes from stream ID %llu\n", nread, stream_id);

        //ignore error, and echo it
        QUIC_set_data_to_stream(c->quic, buf, nread, &stream_id);
        QUIC_write_streams(c->quic);

        event_add(c->read_event, &tv);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_DRAIN) {
        do_draining(c);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_CLOSE) {
        do_disconnect(c);
    }//end if
    else {
        fprintf(stderr, "%s\n", QUIC_get_err(c->quic));
        do_disconnect(c);
    }//end else
}//end do_read

static void do_disconnect(Client *c) {
    int fd;

    fd = c->fd;
    printf("Client [%s]:%s is shutting down\n", c->addr_str, c->port_str);
    QUIC_shutdown(c->quic);
    client_list[fd] = NULL;
    free_client(c);
}//end di_disconnect

static void do_draining(Client *c) {
    struct timeval tv;

    QUIC_shutdown(c->quic);
    if(!c->draining) {
        printf("Start draining\n");
        c->draining = true;
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        event_add(c->read_event, &tv);
    }//end if
}//end do_draining