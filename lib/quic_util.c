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


#include "quic_internal.h"

static quic_err_t quic_bind_to_local(int fd, sa_family_t family, const char *local_host, const char *local_port, char *errbuf);
static quic_err_t quic_set_reuse_addr_port(int fd, char *errbuf);

void quic_srand(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    srand(ts.tv_sec * 1000000000 ^ ts.tv_nsec);
}//end quic_srand

ngtcp2_tstamp quic_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}//end quic_timestamp

quic_err_t quic_rand(u_int8_t *buf, size_t len) {
    int fd;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(fd < 0) {
        return QUIC_ERR_SYSTEM;
    }//end if

    read(fd, buf, len);
    close(fd);
    return QUIC_ERR_NONE;
}//end quic_rand

void QUIC_timespec_to_timeval(struct timespec *ts, struct timeval *tv) {
    tv->tv_sec  = ts->tv_sec;
    tv->tv_usec = ts->tv_nsec / 1000;
}//end QUIC_timespec_to_timeval

void QUIC_timespec_to_ev_tstamp(struct timespec *ts, double *libev_tstamp) {
    *libev_tstamp = (double)ts->tv_sec + (double)ts->tv_nsec/1000000000.;
}//end QUIC_timespec_to_ev_tstamp

int QUIC_connect_fd_to_host(sa_family_t family, const char *local_host, const char *local_port, const char *remote_host, const char *remote_port, char *errbuf) {
    int             ret, fd;
    struct addrinfo hints, *res, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    ret = getaddrinfo(remote_host, remote_port, &hints, &res);
    if(ret != 0) {
        quic_set_gai_err(errbuf, "getaddrinfo", ret);
        return -1;
    }//end if

    fd = -1;
    for(rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd == -1) {
            quic_set_sys_err(errbuf, "socket", errno);
            continue;
        }//end if

        if(quic_set_reuse_addr_port(fd, errbuf) != QUIC_ERR_NONE) {
            close(fd);
            continue;
        }//end if

        if(local_host || local_port) {
            if(quic_bind_to_local(fd, rp->ai_family, local_host, local_port, errbuf) != QUIC_ERR_NONE) {
                close(fd);
                continue;
            }//end if
        }//end if

        if(connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
            quic_set_sys_err(errbuf, "connect", errno);
            close(fd);
            continue;
        }//end if

        break;
    }//end for

    if(!rp) {
        freeaddrinfo(res);
        return -1;
    }//end if

    freeaddrinfo(res);
    return fd;
}//end QUIC_connect_fd_to_host

int QUIC_connect_fd_to_addr(struct sockaddr_storage *local_addr, socklen_t local_addr_len, struct sockaddr_storage *remote_addr, socklen_t remote_addr_len, char *errbuf) {
    int fd;

    fd = socket(remote_addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if(fd < 0) {
        quic_set_sys_err(errbuf, "socket", errno);
        return -1;
    }//end if

    if(quic_set_reuse_addr_port(fd, errbuf) != QUIC_ERR_NONE) {
        close(fd);
        return -1;
    }//end if

    if(local_addr && local_addr_len > 0) {
        if(bind(fd, (struct sockaddr *)local_addr, local_addr_len) == -1) {
            quic_set_sys_err(errbuf, "bind", errno);
            close(fd);
            return -1;
        }//end if
    }//end if

    if(connect(fd, (struct sockaddr *)remote_addr, remote_addr_len) == -1) {
        quic_set_sys_err(errbuf, "connect", errno);
        close(fd);
        return -1;
    }//end if

    return fd;
}//end QUIC_connect_fd_to_addr

int QUIC_bind_fd_to_host(sa_family_t family, const char *host, const char *port, char *errbuf) {
    int             ret, fd, val;
    struct addrinfo hints, *res, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    ret = getaddrinfo(host, port, &hints, &res);
    if(ret != 0) {
        quic_set_gai_err(errbuf, "getaddrinfo", ret);
        return -1;
    }//end if

    fd = -1;
    val = 1;
    for(rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd == -1) {
            quic_set_sys_err(errbuf, "socket", errno);
            continue;
        }//end if

        if(rp->ai_family == PF_INET6) {
            if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, (socklen_t)sizeof(val)) == -1) {
                quic_set_sys_err(errbuf, "setsockopt IPV6_V6ONLY", errno);
                close(fd);
                continue;
            }//end if
        }//end if

        if(quic_set_reuse_addr_port(fd, errbuf) != QUIC_ERR_NONE) {
            close(fd);
            continue;
        }//end if

        if(bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
            quic_set_sys_err(errbuf, "bind", errno);
            close(fd);
            continue;
        }//end if

        break;
    }//end for
    if(!rp) {
        freeaddrinfo(res);
        return -1;
    }//end if

    freeaddrinfo(res);
    return fd;
}//end QUIC_bind_fd_to_host

int QUIC_bind_fd_to_addr(struct sockaddr_storage *addr, socklen_t addr_len, char *errbuf) {
    int fd, val;

    fd = socket(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if(fd < 0) {
        quic_set_sys_err(errbuf, "socket", errno);
        return -1;
    }//end if

    val = 1;
    if(addr->ss_family == PF_INET6) {
        if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, (socklen_t)sizeof(val)) == -1) {
            quic_set_sys_err(errbuf, "setsockopt IPV6_V6ONLY", errno);
            close(fd);
            return -1;
        }//end if
    }//end if

    if(quic_set_reuse_addr_port(fd, errbuf) != QUIC_ERR_NONE) {
        close(fd);
        return -1;
    }//end if

    if(bind(fd, (struct sockaddr *)addr, addr_len) == -1) {
        quic_set_sys_err(errbuf, "bind", errno);
        close(fd);
        return -1;
    }//end if

    return fd;
}//end QUIC_bind_fd_to_addr

void QUIC_get_addr_in_preaccept(struct sockaddr_storage *addr, socklen_t *addr_len, QUIC_PREACCEPT *pre_data) {
    memcpy(addr, &(pre_data->addr.ss), sizeof(struct sockaddr_storage));
    *addr_len = pre_data->addr.len;
}//end QUIC_get_addr_in_preaccept


/* ===== private function ===== */
static quic_err_t quic_bind_to_local(int fd, sa_family_t family, const char *local_host, const char *local_port, char *errbuf) {
    int             ret;
    quic_err_t      err;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    ret = getaddrinfo(local_host, local_port, &hints, &res);
    if(ret != 0) {
        quic_set_gai_err(errbuf, "getaddrinfo", ret);
        return QUIC_ERR_SYSTEM;
    }//end if

    err = QUIC_ERR_NONE;
    if(bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
        quic_set_sys_err(errbuf, "bind", errno);
        err = QUIC_ERR_SYSTEM;
    }//end if

    freeaddrinfo(res);
    return err;
}//end quic_bind_to_local

static quic_err_t quic_set_reuse_addr_port(int fd, char *errbuf) {
    int val;

    val = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, (socklen_t)sizeof(val)) == -1) {
        quic_set_sys_err(errbuf, "setsockopt SO_REUSEADDR", errno);
        return QUIC_ERR_SYSTEM;
    }//end if

    if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, (socklen_t)sizeof(val)) == -1) {
        quic_set_sys_err(errbuf, "setsockopt SO_REUSEPORT", errno);
        return QUIC_ERR_SYSTEM;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_set_reuse_addr_port