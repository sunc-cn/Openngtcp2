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


#ifndef QUIC_INTERNAL_H
#define QUIC_INTERNAL_H

/* standard */
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

/* openngtcp2 */
#include <openngtcp2.h>

/* openssl */
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>

/* ngtcp2 */
#include <ngtcp2/ngtcp2.h>

/* quic internal header */
#include "quic_err.h"
#include "quic_list.h"
#include "quic_deque.h"
#include "quic_buf.h"
#include "quic_byte_array.h"
#include "quic_stream.h"
#include "quic_stream_map.h"
#include "quic_crypto.h"
#include "quic_ctx.h"
#include "quic.h"
#include "quic_ssl_bio.h"
#include "quic_io.h"
#include "quic_util.h"
#include "quic_ngtcp2_callback.h"
#include "quic_ssl_callback.h"

#endif /* QUIC_INTERNAL_H */