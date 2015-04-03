#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(recvmail,1.2,devel@heily.com)
AC_CANONICAL_SYSTEM()
AM_INIT_AUTOMAKE(recvmail, 1.2)
AC_CONFIG_SRCDIR([recvmail.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/file.h sys/socket.h sys/time.h syslog.h unistd.h event.h sys/capability.h])

# Check for the Capsicum security mechanism
AC_CHECK_HEADER([sys/capability.h])

# Require libevent
PKG_CHECK_MODULES([LIBEVENT], [libevent > 2])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([alarm dup2 gethostbyaddr gethostbyname gethostname gettimeofday inet_ntoa memset mkdir socket strchr strerror strncasecmp strstr crypt srandomdev])

# Some platforms (e.g. Linux) have crypt(3) in a separate library
AC_CHECK_LIB(crypt, crypt, external_crypt=yes, external_crypt=no)

# Check for systrace(1)
AC_CHECK_FILES(/dev/systrace)
AM_CONDITIONAL(HAVE_SYSTRACE, test x$ac_cv_file__dev_systrace = xyes)

# Automake macros
AM_CONDITIONAL(WITH_LIBCRYPT, test x$external_crypt = xyes)
AM_CONDITIONAL(MULTITHREADED, test x$ac_cv_header_pthread_h = xyes)

# User-configurable options
#---------------------------------------

AC_ARG_WITH([uid],
		AC_HELP_STRING([--with-uid], [The default user-ID to run as]),
		[ac_cv_use_uid=$withval], [ac_cv_use_uid="_recvmail"])
AC_DEFINE_UNQUOTED(UID, "$ac_cv_use_uid", [The user-ID for recvmail(8)])

AC_ARG_WITH([gid],
		AC_HELP_STRING([--with-gid], [The default group-ID to run as]),
		[ac_cv_use_gid=$withval], [ac_cv_use_gid="vmail"])
AC_DEFINE_UNQUOTED(GID, "$ac_cv_use_gid", [The group-ID for recvmail(8)])

#---------------------------------------
#

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
