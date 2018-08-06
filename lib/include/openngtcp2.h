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


#ifndef OPENNGTCP2_H
#define OPENNGTCP2_H

/* standard */
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>

/* openssl */
#include <openssl/ssl.h>

/* ngtcp2 */
#include <ngtcp2/ngtcp2.h>

/* openngtcp2 */
#include <openngtcp2/openngtcp2_version.h>
#include <openngtcp2/openngtcp2_quic_common.h>
#include <openngtcp2/openngtcp2_quic_err.h>
#include <openngtcp2/openngtcp2_quic_ctx.h>
#include <openngtcp2/openngtcp2_quic.h>
#include <openngtcp2/openngtcp2_quic_crypto.h>
#include <openngtcp2/openngtcp2_quic_util.h>
#include <openngtcp2/openngtcp2_quic_ctx_ctrl.h>
#include <openngtcp2/openngtcp2_quic_ctrl.h>

#endif /* OPENNGTCP2_H */