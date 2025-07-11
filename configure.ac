AC_PREREQ([2.69])
AC_INIT([uadk], [2.9.1], [liguozhu@hisilicon.com])
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
AC_SUBST([hardcode_into_libs], [no])
AM_PROG_CC_C_O

# Support assembler
AM_PROG_AS

AC_ARG_ENABLE([debug-log],
	AS_HELP_STRING([--enable-debug-log], [enable debug logging globally]),
	[ AS_IF([test "x$enable_debug_log" = "xyes"],
		AC_DEFINE(DEBUG_LOG, 1, [Enable debug log])
		debug_log=true,
		debug_log=false)
	],
	[debug_log=false]
)

AC_ARG_ENABLE([perf],
	AS_HELP_STRING([--disble-perf], [enable measuring performance]),
	[ AS_IF([test "x$enable_perf" = "xyes"],
		AC_DEFINE(HAVE_PERF, 1, [Support for measuring performance])
		perf=true
	],
	[perf=false])
  [perf=false]
)

AC_CANONICAL_HOST
AS_IF([test "$host_cpu" = "aarch64"],[
     arch_arm64="true"
])
AM_CONDITIONAL([ARCH_ARM64], [test "x$arch_arm64" = "xtrue"])

AC_MSG_NOTICE([Detected host_cpu: $host_cpu])

AC_CHECK_LIB(z, zlibVersion,
	     [ AC_DEFINE(HAVE_ZLIB, 1, [Have zlib])
	       have_zlib=true ],
	     [ have_zlib=false ])
AM_CONDITIONAL([HAVE_ZLIB], [test "x$have_zlib" = "xtrue"])

PKG_CHECK_MODULES(libcrypto, libcrypto < 3.0 libcrypto >= 1.1,
	     [ AC_DEFINE(HAVE_CRYPTO, 1, [Have crypto])
	       have_crypto=true ],
	     [ have_crypto=false ])
AM_CONDITIONAL([HAVE_CRYPTO], [test "x$have_crypto" = "xtrue"])

AC_ARG_WITH(log_file,
	AS_HELP_STRING([--with-log_file], [File to write log]),
	WITH_LOG_FILE=$withvar, WITH_LOG_FILE=)
AC_SUBST(with_log_file)
AM_CONDITIONAL([WITH_LOG_FILE], [test -n "$with_log_file"])

AC_ARG_WITH(static_drv,
	AS_HELP_STRING([--with-static_drv], [Built as static library]),
	WD_STATIC_DRV=$withvar, WD_STATIC_DRV=)
AC_SUBST(with_static_drv)
AM_CONDITIONAL([WD_STATIC_DRV], [test -n "$with_static_drv"])

AC_ARG_WITH(zlib_fse_dir,
	AS_HELP_STRING([--with-zlib_fse_dir], [Path to Zlib FSE library]))
AC_SUBST(with_zlib_fse_dir)
AM_CONDITIONAL([WITH_ZLIB_FSE_DIR], [test -n "$with_zlib_fse_dir"])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/time.h unistd.h])

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
AC_CHECK_FUNCS([gettimeofday memmove memset munmap strstr strtoul strtoull])

AC_CONFIG_FILES([Makefile
		 lib/libwd_crypto.pc lib/libwd_comp.pc lib/libwd.pc
		 test/Makefile
		 test/hisi_hpre_test/Makefile
		 uadk_tool/Makefile
		 sample/Makefile
		 v1/test/Makefile
		 v1/test/bmm_test/Makefile
		 v1/test/test_mm/Makefile
		 v1/test/hisi_hpre_test/Makefile
		 v1/test/hisi_sec_test/Makefile
		 v1/test/hisi_sec_test_sgl/Makefile
		 v1/test/hisi_zip_test/Makefile
		 v1/test/hisi_zip_test_sgl/Makefile])
AC_OUTPUT
