AC_INIT([HIPDEX-VPN], [0.1], [jpellikk@users.noreply.github.com],
        [hipdex_vpn_cpp], [https://github.com/jpellikk/hipdex-vpn])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([1.11 -Wall no-define])

AC_LANG([C++])

AC_DEFUN([AC_DEFINE_DIR], [
  test "x$prefix" = xNONE && prefix="$ac_default_prefix"
  test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
  ac_define_dir=`eval echo [$]$2`
  ac_define_dir=`eval echo [$]ac_define_dir`
  $1="$ac_define_dir"
  AC_SUBST($1)
  AC_DEFINE_UNQUOTED($1, "$ac_define_dir/hipdex-vpn", $3)
])

AC_DEFINE_DIR(PACKAGE_CONFDIR, sysconfdir, [Configuration file directory])

AC_CONFIG_HEADERS([config.h])

AM_MISSING_PROG([AUTOM4TE], [autom4te])
AC_CONFIG_MACRO_DIR([m4])

AX_CXX_COMPILE_STDCXX_11([ext],[mandatory])

AC_PROG_GREP
AC_PROG_CXX

AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_FUNC_VPRINTF

PKG_CHECK_MODULES([jansson], [jansson >= 2.2.1])
PKG_CHECK_MODULES([libnl], [libnl-3.0 >= 3.0])
PKG_CHECK_MODULES([libnlroute], [libnl-route-3.0 >= 0.26])
PKG_CHECK_MODULES([openssl], [openssl >= 1.0.1e])

AC_SUBST(AM_CFLAGS, "-Wall -Wextra")

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
