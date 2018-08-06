#
# openngtcp2
#
# Copyright (C) 2018, TUTU 
#
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions: 
#
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software. 
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL 
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE. 
#

SUBDIRS = include

AM_CFLAGS = $(WARNCFLAGS) $(DEBUGCFLAGS) $(OPENSSL_CFLAGS) $(NGTCP2_CFLAGS) $(EXTRACFLAG) $(DEFAULT_CFLAGS)
AM_CPPFLAGS = -I$(srcdir)/include -I$(builddir)/include -DBUILDING_OPENNGTCP2

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libopenngtcp2.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libopenngtcp2.la

OBJECTS = \
	quic_ctx.c \
    quic.c \
    quic_ssl_bio.c \
    quic_crypto.c \
    quic_util.c \
    quic_ngtcp2_callback.c \
    quic_deque.c \
    quic_list.c \
    quic_buf.c \
    quic_byte_array.c \
    quic_io.c \
    quic_stream.c \
    quic_stream_map.c \
    quic_client.c \
    quic_bio.c \
    quic_ssl_callback.c \
    quic_server.c \
    quic_ctx_ctrl.c \
    quic_ctrl.c

HFILES = \
    quic_internal.h \
	quic_ctx.h \
    quic.h \
    quic_err.h \
    quic_ssl_bio.h \
    quic_crypto.h \
    quic_util.h \
    quic_ngtcp2_callback.h \
    quic_deque.h \
    quic_list.h \
    quic_buf.h \
    quic_byte_array.h \
    quic_io.h \
    quic_stream.h \
    quic_stream_map.h \
    quic_ssl_callback.h

libopenngtcp2_la_SOURCES = $(HFILES) $(OBJECTS)
libopenngtcp2_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
