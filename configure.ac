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

AC_PREREQ(2.61)
AC_INIT([openngtcp2], [0.12.0-dev], [jr89197@hotmail.com])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS

LT_PREREQ([2.2.6])
LT_INIT()

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([subdir-objects])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# See versioning rule:
#  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 0)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 0)

# from nghttp2
major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

# Checks for command-line options
AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [Turn on compile time warnings])],
    [werror=$enableval], [werror=no])

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [Turn on debug output])],
    [debug=$enableval], [debug=no])

if test "x${debug}" = "x${enableval}"; then
  DEBUGCFLAGS="-O0 -g3"
  AC_SUBST([DEBUGCFLAGS])
fi

DEFAULT_CFLAGS="-Wall"
AC_SUBST([DEFAULT_CFLAGS])

# Checks for programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

PKG_PROG_PKG_CONFIG([0.20])

# Checks for libraries.

# openssl
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.1],
                  [have_openssl=yes], [have_openssl=no])
if test "x${have_openssl}" = "xno"; then
  AC_MSG_ERROR(["OpenSSL is not found, or version is under 1.1.1"])
fi

# ngtcp2
PKG_CHECK_MODULES([NGTCP2], [libngtcp2],
                  [have_ngtcp2=yes], [have_ngtcp2=no])
if test "x${have_ngtcp2}" = "xno"; then
  AC_MSG_ERROR(["ngtcp2 is not found"])
fi

# libevent (for examples)
PKG_CHECK_MODULES([LIBEVENT], [libevent],
                  [have_libevent=yes], [have_libevent=no])
if test "x${have_libevent}" = "xno"; then
  AM_CONDITIONAL([HAVE_LIBEVENT], [ test "x${have_libevent}" = "xno" ])
else
  AM_CONDITIONAL([HAVE_LIBEVENT], [ test "x${have_libevent}" = "xyes" ])
fi

# Checks for header files.
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  stddef.h \
  stdint.h \
  stdlib.h \
  string.h \
  unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_OFF_T
AC_C_BIGENDIAN
AC_C_INLINE
AC_SYS_LARGEFILE

# Checks for library functions.
AC_CHECK_FUNCS([ \
  memmove \
  memset \
])

# debug build
if test "x$debug" != "xno"; then
    AC_DEFINE([DEBUGBUILD], [1], [Define to 1 to enable debug output.])
fi

AC_CONFIG_FILES([
  Makefile
  lib/libopenngtcp2.pc
  lib/Makefile
  lib/include/Makefile
  lib/include/openngtcp2/openngtcp2_version.h
  examples/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

    Package version: ${VERSION}
    Library version: $LT_CURRENT:$LT_REVISION:$LT_AGE
    Install prefix:  ${prefix}
    System types:
      Build:         ${build}
      Host:          ${host}
      Target:        ${target}
    Compiler:
      C preprocessor: ${CPP}
      C compiler:     ${CC}
      CFLAGS:         ${CFLAGS}
      LDFLAGS:        ${LDFLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      EXTRACFLAG:     ${EXTRACFLAG}
      LIBS:           ${LIBS}
    Library:
      Shared:         ${enable_shared}
      Static:         ${enable_static}
    Debug:
      Debug:          ${debug} (CFLAGS='${DEBUGCFLAGS}')
    Libs:
      OpenSSL:        ${have_openssl}   (CFLAGS='${OPENSSL_CFLAGS}' LIBS='${OPENSSL_LIBS}')
      ngtcp2:         ${have_ngtcp2}   (CFLAGS='${NGTCP2_CFLAGS}' LIBS='${NGTCP2_LIBS}')
      Libevent:       ${have_libevent}   (CFLAGS='${LIBEVENT_CFLAGS}' LIBS='${LIBEVENT_LIBS}')
])
