#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)

AC_INIT(tdor, 0.0.8, cviecco@indiana.edu)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
#AC_CONFIG_SRCDIR([util.h])
AC_CONFIG_HEADER([config.h])


AC_CANONICAL_HOST
if test -n "$target"; then
  AC_CANONICAL_TARGET
fi


#---------------
# checks for host?
#----------
case "$host" in
  *-linux*)
    AC_DEFINE([LINUX],[],[Linux Host])
    ;;
  *-openbsd*)
    AC_DEFINE([OPENBSD],[],[OpenBSD Host])
    ;;
  *-solaris*)
    AC_DEFINE([SOLARIS],[],[Solaris Host])
    ;;
  *-freebsd*)
    AC_DEFINE([FREEBSD],[],[FreeBSD Host])
    ;;
  *-apple*)
    AC_DEFINE([MACOS],[],[MacOSX Host])
esac

##stdlib check
AM_PROG_CC_STDC

#---------------------------------------------------------
# Checks for programs.
#---------------------------------------------------------
AC_PROG_CXX

#-----------
# Set manually cpu for cross compile only for gcc and target
#---------

case "$CC" in
  *gcc*)
    if  test -n "$target_cpu"; then
      CFLAGS="${CFLAGS} -march=${target_cpu} "
    fi
    ;;
esac



#---------------------------------------------------------
# Checks for libraries.
#---------------------------------------------------------
# Check for libdnet:
AC_ARG_WITH(libdnet_includes,
    [  --with-libdnet-includes=DIR  libdnet include directory],
    [with_libdnet_includes="$withval"],[with_libdnet_includes=no])

AC_ARG_WITH(libdnet_libraries,
    [  --with-libdnet-libraries=DIR  libdnet library directory],
    [with_libdnet_libraries="$withval"],[with_libdnet_libraries=no])

if test "$with_libdnet_includes" != "no"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libdnet_includes}"
fi
if test "$with_libdnet_libraries" != "no"; then
   LDFLAGS="${LDFLAGS}  -L${with_libdnet_libraries}"
fi

LDNET=""
AC_CHECK_LIB([dnet], [ip_checksum],, LDNET="no")
if test "$LDNET" = "no"; then
  echo
  echo "   ERROR! libdnet library/headers not found, go get it from"
  echo "   http://libdnet.sourceforge.net/"
  echo "   or use the --with-libdnet-* options, if you have it installed"
  echo "   in unusual place"
  exit
fi


# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [fabs])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [pthread_create])

#actually is libcrypto
AC_CHECK_LIB([crypto], [AES_cbc_encrypt])


# Check for ssl
AC_ARG_WITH(libssl_includes,
    [  --with-libssl-includes=DIR  libssl include directory],
    [with_libssl_includes="$withval"],[with_libssl_includes=no])

AC_ARG_WITH(libssl_libraries,
    [  --with-libssl-libraries=DIR  libssl library directory],
    [with_libssl_libraries="$withval"],[with_libssl_libraries=no])

if test "$with_libssl_includes" != "no"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libssl_includes}"
fi
if test "$with_libssl_libraries" != "no"; then
   LDFLAGS="${LDFLAGS}  -L${with_libssl_libraries}"
fi
LSSL=""
AC_CHECK_LIB([ssl], [AES_cbc_encrypt],,LSSL="no")
if test "$LSSL" = "no"; then
  echo
  echo "   ERROR! libssl library/headers not found, go get it from"
  echo "   http://www.openssl.org/"
  echo "   or use the --with-libssl-* options, if you have it installed"
  echo "   in unusual place"
  exit
fi

#libcurl needs zlib? (atleast on mips!)
AC_CHECK_LIB([z], [zlibVersion])



#check for libcurl
#
AC_ARG_WITH(libcurl_includes,
    [  --with-libcurl-includes=DIR  libcurl include directory],
    [with_libcurl_includes="$withval"],[with_libcurl_includes=no])

AC_ARG_WITH(libcurl_libraries,
    [  --with-libcurl-libraries=DIR  libcurl library directory],
    [with_libcurl_libraries="$withval"],[with_libcurl_libraries=no])

if test "$with_libcurl_includes" != "no"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libcurl_includes}"
fi
if test "$with_libcurl_libraries" != "no"; then
   LDFLAGS="${LDFLAGS}  -L${with_libcurl_libraries}"
fi
LCURL=""
AC_CHECK_LIB([curl], [curl_easy_init],,LCURL="no")
if test "$LCURL" = "no"; then
  echo
  echo "   ERROR! libcurl library/headers not found, go get it from"
  echo "   http://curl.haxx.se/"
  echo "   or use the --with-libcurl-* options, if you have it installed"
  echo "   in unusual place"
  exit
fi




#---------------------------------------------------------
# Checks for header files.
#---------------------------------------------------------
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([ifaddrs.h])
AC_CHECK_HEADERS([netinet/in_systm.h])

#---------------------------------------------------------
# Checks for typedefs, structures, and compiler characteristics.
#---------------------------------------------------------
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_CHECK_MEMBERS([struct icmphdr.type],,,[#include <netinet/ip_icmp.h>])
#---------------------------------------------------------
# Checks for library functions.
#---------------------------------------------------------
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([dup2 gethostbyname gettimeofday inet_ntoa memset select socket])
#---------------------------------------------------------
AC_CONFIG_FILES([Makefile ])
AC_OUTPUT
