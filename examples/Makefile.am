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

if HAVE_LIBEVENT
AM_CFLAGS = $(WARNCFLAGS) $(DEBUGCFLAGS) $(DEFAULT_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/lib/include \
	-I$(top_builddir)/lib/include \
    @OPENSSL_CFLAGS@ \
    @NGTCP2_CFLAGS@ \
	@LIBEVENT_CFLAGS@ \
	@DEFS@
AM_LDFLAGS =
LDADD = $(top_builddir)/lib/libopenngtcp2.la \
    @OPENSSL_LIBS@ \
    @NGTCP2_LIBS@ \
	@LIBEVENT_LIBS@

noinst_PROGRAMS = quic_client quic_server

quic_client_SOURCES = quic_client.c

quic_server_SOURCES = quic_server.c

endif # HAVE_LIBEVENT
