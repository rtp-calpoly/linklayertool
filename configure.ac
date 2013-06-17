#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([linklayertool], [0.1], [rtpardavila@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/configuration.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
	then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support]);
fi
AM_CONDITIONAL([HAVE_DOXYGEN],[test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Doxyfile])])

AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_MKDIR_P

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lev':
AC_CHECK_LIB([ev], [main])
# FIXME: Replace `main' with a function in `-levent':
AC_CHECK_LIB([event], [main])

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stddef.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([getpagesize memset munmap socket])

AC_CONFIG_FILES([Makefile docs/Makefile
                 scripts/Makefile
                 src/Makefile])
AC_OUTPUT
