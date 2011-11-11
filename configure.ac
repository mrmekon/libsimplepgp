#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libsimplepgp], [1.0], [trevor@trevorbentley.com])

AC_COPYRIGHT(Trevor Bentley 2011)

AC_CONFIG_SRCDIR([src/packet.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AM_INIT_AUTOMAKE([subdir-objects foreign])

AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC

AC_ARG_WITH(zlib,
  [  --with-zlib=DIR         use libz in DIR],[
    if test -d "$withval"; then
      CPPFLAGS="${CPPFLAGS} -I$withval/include"
      LDFLAGS="${LDFLAGS} -L$withval/lib"
    fi
  ])

AC_CHECK_HEADER(zlib.h,
      AC_CHECK_LIB(z, inflateInit2_,
       ZLIBS="-lz",
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})

# Checks for libraries.
AC_CHECK_LIB([gcrypt],[gcry_md_open],[],[
	echo "libgcrypt is required for this program"
	exit -1])
AC_CHECK_LIB([gpg-error],[gpg_err_init],[],[
	echo "gpg-error is required for this program"
	exit -1])
AC_CHECK_LIB([z],[inflate],[],[
	echo "zlib is required for this program"
	exit -1])


# Checks for header files.
AC_CHECK_HEADERS([locale.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h wchar.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memmove memset setlocale])

AC_OUTPUT
