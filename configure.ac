# This file is part of GNUnet.
# (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2, or (at your
# option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUnet; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ(2.57)
AC_INIT([GNUnet], [0.7.0c],[bug-gnunet@gnu.org])
AM_INIT_AUTOMAKE([GNUnet], [0.7.0c])
AM_CONFIG_HEADER([config.h])

AH_TOP([#define _GNU_SOURCE  1])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_LIBTOOL_WIN32_DLL
AC_CANONICAL_HOST


# dynamic libraries/plugins
AC_LIBTOOL_DLOPEN
AC_LIBLTDL_INSTALLABLE
AC_SUBST(LTDLINCL)
AC_SUBST(LIBLTDL)
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_LIB_LTDL
AC_CONFIG_SUBDIRS(libltdl)

# large file support
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO


if test "$enable_shared" = "no"
then
 AC_MSG_ERROR([GNUnet only works with shared libraries. Sorry.])
fi

CFLAGS="-Wall $CFLAGS"
# use '-fno-strict-aliasing', but only if the compiler can take it
if gcc -fno-strict-aliasing -S -o /dev/null -xc /dev/null >/dev/null 2>&1;
then
 CFLAGS="-fno-strict-aliasing $CFLAGS"
fi


# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(OSX,1,[This is an OS X system])
     CFLAGS="-no-cpp-precomp $CFLAGS"
     LDFLAGS="-flat_namespace -undefined suppress $LDFLAGS"
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     ;;
freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     build_target="freebsd"
     ;;
openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     ;;
netbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
     ;;
*solaris*)
     AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
     AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
     AC_CHECK_LIB(resolv, res_init)
     AC_CHECK_LIB(rt, nanosleep)
     build_target="solaris"
     ;;
*arm-linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
     ;;
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="cygwin"
     AC_PROG_CXX
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_DEFINE_UNQUOTED(_WIN32,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined -Wl,--export-all-symbols -lws2_32 -lplibc"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="mingw"
     AC_PROG_CXX
     ;;
*)
     AC_MSG_RESULT(Unrecognised OS $host_os)
     AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
;;
esac

AC_MSG_CHECKING([for build target])
AM_CONDITIONAL(CYGWIN,  test "$build_target" = "cygwin")
AM_CONDITIONAL(MINGW,   test "$build_target" = "mingw")
AM_CONDITIONAL(SOLARIS, test "$build_target" = "solaris")
AM_CONDITIONAL(XFREEBSD, test "$build_target" = "freebsd")
AC_MSG_RESULT([$build_target])

# We define the paths here, because MinGW/GCC expands paths
# passed through the command line ("-DDATADIR=..."). This would
# lead to hard-coded paths ("C:\mingw\mingw\bin...") that do
# not contain the actual GNUnet installation. GNUnet usually lives in
# "C:\Program Files\GNU\GNUnet\bin".
AC_DEFINE_DIR([DATADIR], [datadir/GNUnet/], [The directory for installing read-only architecture-independent data])
AC_DEFINE_DIR([LOCALEDIR], [datadir/locale/], [gettext catalogs])


CHECK_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"


# some other checks for standard libs
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, log)
AC_CHECK_LIB(c, getloadavg, AC_DEFINE(HAVE_GETLOADAVG,1,[getloadavg supported]))

# 'save' libs; only those libs found so far will be
# linked against _everywhere_.  For the others, we
# will be more selective!
SAVE_LIBS=$LIBS

AC_CHECK_LIB(gmp, __gmpz_import,, AC_MSG_ERROR([GNUnet requires the GNU MP library (libgmp)]))

# pthread_t is a struct since 11/2004
AC_CHECK_MEMBER(pthread_t.p, AC_DEFINE(HAVE_NEW_PTHREAD_T, 1,
  [Define if you have a post 11/2004 pthread library]), , [#include <pthread.h>])

# libgcrypt
gcrypt=0
AC_MSG_CHECKING(for libgcrypt)
AM_PATH_LIBGCRYPT(1.2.0, gcrypt=1)

if test $gcrypt = 0
then
  AC_MSG_ERROR([GNUnet needs libgcrypt])
fi


# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm],[kvm_open])
AC_CHECK_LIB([kstat],[kstat_open])


# test for libextractor
extractor=0
AC_MSG_CHECKING(for libextractor)
AC_ARG_WITH(extractor,
   [  --with-extractor=PFX    Base of libextractor installation],
   [AC_MSG_RESULT([$with_extractor])
    case $with_extractor in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
            extractor=1))
        ;;
      *)
        LDFLAGS="-L$with_extractor/lib $LDFLAGS"
        CPPFLAGS="-I$with_extractor/include $CPPFLAGS"
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
            EXT_LIB_PATH="-L$with_extractor/lib $EXT_LIB_PATH"
            extractor=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-extractor not specified])
    AC_CHECK_HEADERS(extractor.h,
     AC_CHECK_LIB([extractor], [EXTRACTOR_loadDefaultLibraries],
      extractor=1))])
if test "$extractor" != 1
then
 AC_MSG_ERROR([GNUnet requires libextractor])
fi

SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS

# test for sqlite
sqlite=false
AC_MSG_CHECKING(for SQLite)
AC_ARG_WITH(sqlite,
  [  --with-sqlite=PFX   Base of SQLite installation],
  [AC_MSG_RESULT("$with_sqlite")
   case $with_sqlite in
   no)
     ;;
   yes)
    AC_CHECK_HEADERS(sqlite3.h,
     sqlite=true)
     ;;
   *)
    LDFLAGS="-L$with_sqlite/lib $LDFLAGS"
    CPPFLAGS="-I$with_sqlite/include $CPPFLAGS"
    AC_CHECK_HEADERS(sqlite3.h,
     EXT_LIB_PATH="-L$with_sqlite/lib $EXT_LIB_PATH"
     SQLITE_LDFLAGS="-L$with_sqlite/lib"
     SQLITE_CPPFLAGS="-I$with_sqlite/include"
     sqlite=true)
    LDFLAGS=$SAVE_LDFLAGS
    CPPFLAGS=$SAVE_CPPFLAGS
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with-sqlite not specified])
    AC_CHECK_HEADERS(sqlite3.h, sqlite=true)])
AM_CONDITIONAL(HAVE_SQLITE, test x$sqlite = xtrue)
AC_SUBST(SQLITE_CPPFLAGS)
AC_SUBST(SQLITE_LDFLAGS)


# test for libz (maybe required for linking mysql)
zlib=1
AC_CHECK_LIB(z, compress,,zlib=0)
AM_CONDITIONAL(HAVE_ZLIB, test x$zlib = x1)

# mysql & windows
AC_CHECK_TYPES([sigset_t, off_t], [], [], [#include <sys/types.h>])
AC_CHECK_TYPES([size_t], [], [], [#include <stdio.h>])

if test "$build_target" = "mingw"
then
  CYGWIN_MYSQL_MAGIC="#include <mysql/my_global.h>"
fi

# test for mysql
mysql=false
mysqlfail=false
SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS
AC_MSG_CHECKING(for mysql)
AC_ARG_WITH(mysql,
  [  --with-mysql=PFX   Base of mysql installation],
  [AC_MSG_RESULT("$with_mysql")
   if test "$with_mysql" != "no"
   then
    if test "$with_mysql" != "yes"
    then
      LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql $LDFLAGS $ZLIBS"
      CPPFLAGS="-I$with_mysql/include $CPPFLAGS"
    fi
    AC_CHECK_HEADERS(mysql/mysql.h,
     AC_CHECK_LIB(mysqlclient, mysql_init,
      MYSQL_LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql"
      MYSQL_CPPFLAGS="-I$with_mysql/include"

      mysql=true), [], [$CYGWIN_MYSQL_MAGIC])
   fi
  ],
  [AC_MSG_RESULT([--with-mysql not specified])
   LDFLAGS="-L/usr/lib/mysql $LDFLAGS $ZLIBS"
   AC_CHECK_LIB(mysqlclient, mysql_init,
    [AC_CHECK_HEADERS(mysql/mysql.h,
      MYSQL_LDFLAGS="-L/usr/lib/mysql"
      mysql=true

     , [], [$CYGWIN_MYSQL_MAGIC])])
  ])

AC_SUBST(MYSQL_LDFLAGS)
AC_SUBST(MYSQL_CPPFLAGS)

# additional version check for mysql
if test "$mysql" = "true"
then
  AC_MSG_CHECKING(mysql version)
  AC_RUN_IFELSE([AC_LANG_PROGRAM(
    [[$CYGWIN_MYSQL_MAGIC
      #include <mysql/mysql.h>]],
    [[if (MYSQL_VERSION_ID < 40100)
        return(-1);
      else
        return(0);
    ]])
    ],mysql=true,mysql=false)
  if test "$mysql" = "false"
  then
    mysqlfail=true
    AC_MSG_RESULT([fail, >= 4.1 required])
  else
    AC_MSG_RESULT(ok)
  fi
fi
AM_CONDITIONAL(HAVE_MYSQL, test x$mysql = xtrue)

LDFLAGS=$SAVE_LDFLAGS
CPPFLAGS=$SAVE_CPPFLAGS

# GNUnet Setup
curses=1
pdcurses=0
AC_CHECK_HEADER([ncurses.h], [AC_DEFINE([CURSES_LOC], [<ncurses.h>], [Curses location])],
 [AC_CHECK_HEADER([ncurses/ncurses.h], AC_DEFINE([CURSES_LOC], [<ncurses/ncurses.h>]),
 [AC_CHECK_HEADER([curses.h], AC_DEFINE([CURSES_LOC], [<curses.h>]),
 [AC_CHECK_HEADER([ncurses/curses.h], AC_DEFINE([CURSES_LOC], [<ncurses/curses.h>]),
 curses=0)])])])
AC_CHECK_LIB(ncurses, scrollok,,AC_CHECK_LIB(pdcurses, scrollok,pdcurses=1,curses=0))
AC_DEFINE_UNQUOTED([HAVE_CURSES], $curses, [We have curses])
AM_CONDITIONAL(HAVE_CURSES, test x$curses = x1)
AM_CONDITIONAL(HAVE_PDCURSES, test x$pdcurses = x1)

# check for gtk >= 2.6.0
AC_MSG_CHECKING(for gtk)
AM_PATH_GTK_2_0(2.6.0,without_gtk=false,without_gtk=true)
AM_CONDITIONAL(HAVE_GTK, test x$without_gtk != xtrue)
if test $without_gtk != true
then
 AC_DEFINE_UNQUOTED([HAVE_GTK], 1, [We have GTK])
fi

# check for gettext
AM_GNU_GETTEXT_VERSION(0.13)
AM_GNU_GETTEXT([external])


# Checks for standard header files.
AC_HEADER_DIRENT
AC_HEADER_STDC

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS([fcntl.h math.h errno.h limits.h stdio.h locale.h sys/stat.h sys/types.h pthread.h],,AC_MSG_ERROR([Compiling GNUnet requires standard UNIX headers files]))

# Checks for headers that are only required on some systems or opional (and where we do NOT abort if they are not there)
AC_CHECK_HEADERS([langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/vfs.h arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h sys/file.h])

# Check for GMP header (and abort if not present)
AC_CHECK_HEADERS([gmp.h],,AC_MSG_ERROR([Compiling GNUnet requires gmp.h (from the GNU MP library, libgmp)]))


# Checks for standard typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM




# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_CHECK_FUNCS([floor gethostname memmove rmdir strncasecmp strrchr strtol atoll dup2 fdatasync ftruncate gethostbyname gettimeofday memset mkdir mkfifo select socket strcasecmp strchr strdup strerror strstr clock_gettime getrusage rand uname setlocale getcwd mktime gmtime_r gmtime strlcpy strlcat ftruncate])

# restore LIBS
LIBS=$SAVE_LIBS

AC_SUBST(CPPFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LDFLAGS)
AC_SUBST(EXT_LIB_PATH)
AC_SUBST(EXT_LIBS)

# check for IPv6
ipv6=1
AC_MSG_CHECKING([whether to enable ipv6])
AC_ARG_ENABLE(ipv6,
 [AC_HELP_STRING([--enable-ipv6],[Enable ipv6 support])
  AC_HELP_STRING([--disable-ipv6],[Disable ipv6 support])],
 [case "$enableval" in
  no)	AC_MSG_RESULT(no)
        ipv6=0
	;;
  *)    AC_MSG_RESULT(yes)
  			AC_CHECK_LIB(resolv, gethostbyname2, ipv6=1, ipv6=0)
	;;
  esac],
  [     AC_MSG_RESULT(yes)
  			AC_CHECK_LIB(resolv, gethostbyname2, ipv6=1, ipv6=0)])
AM_CONDITIONAL(HAVE_IPV6, test x$ipv6 != x0)
AC_DEFINE_UNQUOTED(USE_IPV6, $ipv6, [IPV6 available])

# check for guile

AC_ARG_ENABLE(guile,
              [AC_HELP_STRING([--enable-guile],
	                      [Install Guile scripts.])],
	      enable_guile=$enableval)

# By default, enable Guile
if test -z $enable_guile
then
    enable_guile="yes"
fi

guile=0
if test "$enable_guile" = "yes"
then
    AC_PATH_PROG([guile_available], [guile])
    if test -z "$guile_available"
    then
	AC_MSG_WARN([Guile not available, so `gnunet-download-manager' won't be installed.])
    else
	# Perform the whole Guile feature tests
	GUILE_PROGS
        guile=1
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 format)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 regex)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 and-let-star)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 pretty-print)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 documentation)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi
	GUILE_MODULE_AVAILABLE(module_available,[(ice-9 optargs)])
        if test "$module_available" = "no";
	then
          AC_MSG_WARN([required guile module not available])
	  guile=0
        fi

	# Check that the keywork syntax used by (ice-9 optargs) is `#:keywork'
	# (as in Guile 1.6) and not `#!' (as in Guile 1.4)
	GUILE_MODULE_CHECK([guile_pound_colon_keywords],
			   [(ice-9 optargs)],
			   [(lambda* (foo [#]:optional (o [#t])) o)],
			   [Guile 1.6's optarg keyword style is supported])
	if test $guile_pound_colon_keywords != "yes"
	then
	   AC_MSG_WARN([`(ice-9 optargs)' doesn't support the `[#:]' keyword syntax.  Upgrade to Guile 1.6 or later.]);
	  guile=0
        else
          guile=1
	fi
    fi
fi # enable_guile
AM_CONDITIONAL(HAVE_GUILE, test x$guile != x0)

AC_CONFIG_FILES([ po/Makefile.in m4/Makefile
Makefile
contrib/Makefile
doc/Makefile
doc/man/Makefile
src/Makefile
src/include/Makefile
src/applications/Makefile
src/applications/advertising/Makefile
src/applications/bootstrap_http/Makefile
src/applications/chat/Makefile
src/applications/datastore/Makefile
src/applications/dht/Makefile
src/applications/dht/tools/Makefile
src/applications/dht/module/Makefile
src/applications/fragmentation/Makefile
src/applications/fs/Makefile
src/applications/fs/ecrs/Makefile
src/applications/fs/fsui/Makefile
src/applications/fs/lib/Makefile
src/applications/fs/module/Makefile
src/applications/fs/tools/Makefile
src/applications/gap/Makefile
src/applications/getoption/Makefile
src/applications/identity/Makefile
src/applications/kvstore_sqlite/Makefile
src/applications/pingpong/Makefile
src/applications/rpc/Makefile
src/applications/session/Makefile
src/applications/sqstore_mysql/Makefile
src/applications/sqstore_sqlite/Makefile
src/applications/stats/Makefile
src/applications/tbench/Makefile
src/applications/testbed/Makefile
src/applications/template/Makefile
src/applications/topology_default/Makefile
src/applications/topology_f2f/Makefile
src/applications/tracekit/Makefile
src/applications/traffic/Makefile
src/applications/transport/Makefile
src/conf/Makefile
src/server/Makefile
src/transports/Makefile
src/util/Makefile
src/util/win/Makefile
])
AC_OUTPUT

# Finally: summary!

# warn user if mysql found but not used due to version
if test "$mysqlfail" = "true"
then
  AC_MSG_NOTICE([NOTICE: MySQL found, but too old. MySQL support will not be compiled.])
fi

# guile
if test "x$guile" = "x0"
then
  AC_MSG_NOTICE([NOTICE: Guile not found, gnunet-download-manager will not be installed.])
fi

if test "$ipv6" = "0"
then
  AC_MSG_NOTICE([NOTICE: IPv6 support will NOT be compiled.])
fi

AC_MSG_NOTICE([NOTICE: Database support is set to MySQL: $mysql, SQLite: $sqlite])
