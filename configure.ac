AC_PREREQ([2.69])
AC_INIT([wrapdrive], [0.1], [liguozhu@hisilicon.com])
AC_CONFIG_SRCDIR([wd.c])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AM_PROG_AR
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL
LT_INIT
AM_PROG_CC_C_O

AC_ARG_ENABLE([sva],
	AS_HELP_STRING([--disable-sva], [enable support for SVA]),
	[ AS_IF([test "x$enable_sva" = "xyes"],
		AC_DEFINE(ENABLE_SVA, 1, [Support for SVA])
		sva=true
	],
	[sva=false])
  ],
  [sva=false]
)

AC_ARG_WITH(openssl_dir,
	AS_HELP_STRING([--with-openssl_dir], [Path to OpenSSL source code]))
AC_SUBST(with_openssl_dir)

AM_CONDITIONAL([WITH_OPENSSL_DIR], [test -n "$with_openssl_dir"])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/ioctl.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap])

AC_CONFIG_FILES([Makefile
                 test/Makefile
                 test/hisi_hpre_test/Makefile])
AC_OUTPUT
