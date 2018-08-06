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

static struct event_base *base = NULL;
static struct event *read_event = NULL, *write_event = NULL;
static bool send_shutdown = true;
static void usage(const char *cmd);
static void signal_cb(int sig, short what, void *arg);
static int create_socket(sa_family_t family, const char *host, const char *port);
static QUIC *create_QUIC(QUIC_CTX *quic_ctx, int fd, const char *host, const char *session_file, const char *tp_file);
static int use_libevent(QUIC *quic);
static void read_handler(int fd, short event, void *arg);
static void write_handler(int fd, short event, void *arg);
static void do_handshake(QUIC *quic, bool timeout);
static void do_write(QUIC *quic);
static void do_read(QUIC *quic);

int main(int argc, char *argv[]) {
    int         c, fd, ret, data_len;
    QUIC        *quic;
    char        errbuf[QUIC_ERRBUF_SIZE];
    QUIC_CTX    *quic_ctx;
    u_int64_t   stream_id = -1;
    quic_err_t  err;
    const char  *host = NULL, *port = NULL, *session_file = NULL, *tp_file = NULL, *data = NULL;

    opterr = 0;
    while((c = getopt(argc, argv, "h:p:s:t:d:")) != EOF) {
        switch(c) {
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 's':
                session_file = optarg;
                break;
            case 't':
                tp_file = optarg;
                break;
            case 'd':
                data = optarg;
                break;

            default:
                usage(argv[0]);
        }//end switch
    }//end while

    if(!host || !port || !data) {
        usage(argv[0]);
    }//end if

    //open socket
    fd = create_socket(PF_UNSPEC, host, port);
    if(fd < 0) {
        fprintf(stderr, "Fail to connect to [%s]:%s\n", host, port);
        return 1;
    }//end if

    //init QUIC_CTX
    quic_ctx = QUIC_CTX_new(errbuf);
    if(!quic_ctx) {
        fprintf(stderr, "Fail to allocating QUIC_CTX: %s\n", errbuf);
        close(fd);
        return 1;
    }//end if

    //allocate QUIC
    quic = create_QUIC(quic_ctx, fd, host, session_file, tp_file);
    if(!quic) {
        QUIC_free(quic);
        QUIC_CTX_free(quic_ctx);
        close(fd);
        return 1;
    }//end if

    //set data to send(before handshaking is done)
    data_len = strlen(data);
    err = QUIC_set_data_to_stream(quic, (const u_int8_t *)data, data_len, &stream_id);
    if(err != QUIC_ERR_NONE) {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
    }//end if

    //if set data operation is after handshaking is done
    //stream id will be a valid value
    if(stream_id != -1) {
        printf("Stream ID: %llu\n", stream_id);
    }//end if

    //start event loop
    ret = use_libevent(quic);

    //shut it down
    if(send_shutdown) {
        printf("Send shutdown\n");
        err = QUIC_shutdown(quic);
        if(err != QUIC_ERR_NONE) {
            fprintf(stderr, "%s\n", QUIC_get_err(quic));
            ret = 1;
        }//end if
    }//end if

    if(tp_file && QUIC_is_init_finished(quic)) {
        QUIC_write_transport_params_to_file(quic, tp_file);
    }//end if
    if(session_file && QUIC_is_init_finished(quic)) {
        QUIC_write_session_to_file(quic, session_file);
    }//end if

    QUIC_free(quic);
    QUIC_CTX_free(quic_ctx);
    close(fd);
    return ret == 0 ? 0 : 1;
}//end main


/* ===== private function ===== */
static void usage(const char *cmd) {
    fprintf(stderr, "%s [-h host] [-p port] [-d string to send] [-s session file to read and write] [-t transport params file to read and wirte]\n", cmd);
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
    socklen_t   ss_len;
    struct sockaddr_storage ss;

    fd = QUIC_connect_fd_to_host(family, NULL, NULL, host, port, errbuf);
    if(fd < 0) {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }//end if

    memset(&ss, 0, sizeof(ss));
    ss_len = sizeof(ss);
    if(getpeername(fd, (struct sockaddr *)&ss, &ss_len) != 0) {
        perror("getpeername()");
        close(fd);
        return -1;
    }//end if

    //better than inet_ntop()
    ret = getnameinfo(
        (struct sockaddr *)&ss, ss_len,
        addr_str, sizeof(addr_str),
        port_str, sizeof(port_str),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if(ret != 0) {
        fprintf(stderr, "getnameinfo(): %s\n", gai_strerror(ret));
        close(fd);
        return -1;
    }//end if

    printf("Peer address is [%s]:%s\n", addr_str, port_str);

    //set to non-block
    if(evutil_make_socket_nonblocking(fd) != 0) {
        fprintf(stderr, "Fail to set nonblocking\n");
        close(fd);
        return -1;
    }//end if

    return fd;
}//end create_socket

static QUIC *create_QUIC(QUIC_CTX *quic_ctx, int fd, const char *host, const char *session_file, const char *tp_file) {
    char        errbuf[QUIC_ERRBUF_SIZE];
    QUIC        *quic;
    quic_err_t  err;

    quic = QUIC_new_connect(quic_ctx, errbuf);
    if(!quic) {
        fprintf(stderr, "Fail to allocating QUIC: %s\n", errbuf);
        return NULL;
    }//end if

    err = QUIC_set_fd(quic, fd);
    if(err != QUIC_ERR_NONE) {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
        QUIC_free(quic);
        return NULL;
    }//end if

    err = QUIC_set_tlsext_host_name(quic, host);
    if(err != QUIC_ERR_NONE) {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
        QUIC_free(quic);
        return NULL;
    }//end if

    if(session_file) {
        err = QUIC_read_session_from_file(quic, session_file);
        if(err != QUIC_ERR_NONE) {
            fprintf(stderr, "%s\n", QUIC_get_err(quic));
        }//end if
    }//end if

    if(tp_file) {
        err = QUIC_read_transport_params_from_file(quic, tp_file);
        if(err != QUIC_ERR_NONE) {
            fprintf(stderr, "%s\n", QUIC_get_err(quic));
        }//end if
    }//end if

    return quic;
}//end create_QUIC

static int use_libevent(QUIC *quic) {
    int             fd, ret = 0;
    struct event    *sigint_event = NULL, *sigterm_event = NULL;

    fd = QUIC_get_fd(quic);

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

        read_event = event_new(base, fd, EV_READ, read_handler, (void *)quic);
        if(!read_event) {
            fprintf(stderr, "event_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if

        write_event = event_new(base, fd, EV_WRITE, write_handler, (void *)quic);
        if(!read_event) {
            fprintf(stderr, "event_new(): %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            ret = -1;
            break;
        }//end if

        //start handshake
        do_handshake(quic, false);

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
    if(read_event) {
        event_free(read_event);
        read_event = NULL;
    }//end if
    if(write_event) {
        event_free(write_event);
        write_event = NULL;
    }//end if
    if(base) {
        event_base_free(base);
        base = NULL;
    }//end if
    return ret;
}//end use_libevent


bool send_streams = false;

static void read_handler(int fd, short event, void *arg) {
    QUIC *quic;

    quic = (QUIC *)arg;
    if(!QUIC_is_init_finished(quic)) {
        do_handshake(quic, event & EV_TIMEOUT);
    }//end if
    else {
        if(event & EV_TIMEOUT) {
            printf("Timeout!\n");
            event_base_loopbreak(base);
        }//end if
        else {
            do_read(quic);
        }//end else
    }//end else
}//end read_handler

static void write_handler(int fd, short event, void *arg) {
    QUIC *quic;

    quic = (QUIC *)arg;
    if(!QUIC_is_init_finished(quic)) {
        do_handshake(quic, event & EV_TIMEOUT);
    }//end if
    else {
        do_write(quic);
    }//end else
}//end write_handler

static void do_handshake(QUIC *quic, bool timeout) {
    quic_err_t      err;
    struct timeval  tv;
    struct timespec ts;

    if(timeout) {
        err = QUIC_do_retransmit(quic);
    }//end if
    else {
        err = QUIC_do_handshake(quic);
    }//end else

    if(err == QUIC_ERR_QUIC_WANT_READ) {
        ts = QUIC_get_retransmit_timestamp(quic);
        QUIC_timespec_to_timeval(&ts, &tv);
        event_add(read_event, &tv);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_WRITE) {
        event_add(write_event, NULL);
    }//end if
    else if(err == QUIC_ERR_NONE) {
        printf("Handshake is done\n");
        do_write(quic);
    }//end if
    else {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
        event_base_loopbreak(base);
    }//end else
}//end do_handshake

static void do_write(QUIC *quic) {
    quic_err_t      err;
    struct timeval  tv;
    struct timespec ts;

    err = QUIC_write_streams(quic);
    if(err == QUIC_ERR_QUIC_WANT_WRITE) {
        event_add(write_event, NULL);
    }//end if
    else if(err == QUIC_ERR_NONE || err == QUIC_ERR_QUIC_WANT_READ) {
        ts = QUIC_get_retransmit_timestamp(quic);
        QUIC_timespec_to_timeval(&ts, &tv);
        event_add(read_event, &tv);
    }//end if
    else if(err != QUIC_ERR_NONE) {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
        event_base_loopbreak(base);
    }//end else
}//end do_write

static void do_read(QUIC *quic) {
    size_t          nread;
    u_int8_t        buf[65536];
    u_int64_t       stream_id;
    quic_err_t      err;
    struct timeval  tv;

    tv.tv_sec = 30;
    tv.tv_usec = 0;
    err = QUIC_read_stream(quic, buf, sizeof(buf), &nread, &stream_id);
    if(err == QUIC_ERR_QUIC_WANT_READ) {
        event_add(read_event, &tv);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_WRITE) {
        event_add(write_event, NULL);
    }//end if
    else if(err == QUIC_ERR_NONE) {
        printf("Read %zd bytes from stream ID %llu\n", nread, stream_id);
        event_add(read_event, &tv);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_DRAIN) {
        send_shutdown = false;
        printf("Server is sent shutdown\n");
        event_base_loopbreak(base);
    }//end if
    else if(err == QUIC_ERR_QUIC_WANT_CLOSE) {
        event_base_loopbreak(base);
    }//end if
    else {
        fprintf(stderr, "%s\n", QUIC_get_err(quic));
        event_base_loopbreak(base);
    }//end else
}//end do_read