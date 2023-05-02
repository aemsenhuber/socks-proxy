# Initialize
AC_PREREQ([2.69])
AC_INIT([socks-proxy], [git], , , [https://github.com/aemsenhuber/socks-proxy])
AC_CONFIG_AUX_DIR([aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Enable non-standard functions and other goodies
AC_USE_SYSTEM_EXTENSIONS

# Options
# -------

AC_ARG_WITH(c-ares, AS_HELP_STRING([--without-c-ares], [Disable c-ares for asynchronous name resolution]))

# Standard checks
# ---------------

# Programs
AC_PROG_CC

# Headers
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([arpa/inet.h])

# Types
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T

# Functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([socket])

# C-ares
if test "x${with_c_ares}" != xno; then
    AC_DEFINE([ARES], 1, [asynchronous name resolution])
    PKG_CHECK_MODULES(LIBCARES, libcares)
fi

# Output
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
