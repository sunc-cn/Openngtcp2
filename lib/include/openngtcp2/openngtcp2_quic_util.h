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


#ifndef OPENNGTCP2_QUIC_UTIL_H
#define OPENNGTCP2_QUIC_UTIL_H

void QUIC_timespec_to_timeval(struct timespec *ts, struct timeval *tv);
void QUIC_timespec_to_ev_tstamp(struct timespec *ts, double *libev_tstamp);
int QUIC_connect_fd_to_host(sa_family_t family, const char *local_host, const char *local_port, const char *remote_host, const char *remote_port, char *errbuf);
int QUIC_connect_fd_to_addr(struct sockaddr_storage *local_addr, socklen_t local_addr_len, struct sockaddr_storage *remote_addr, socklen_t remote_addr_len, char *errbuf);
int QUIC_bind_fd_to_host(sa_family_t family, const char *host, const char *port, char *errbuf);
int QUIC_bind_fd_to_addr(struct sockaddr_storage *addr, socklen_t addr_len, char *errbuf);
void QUIC_get_addr_in_preaccept(struct sockaddr_storage *addr, socklen_t *addr_len, QUIC_PREACCEPT *pre_data);

#endif /* OPENNGTCP2_QUIC_UTIL_H */