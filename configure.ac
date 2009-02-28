# This file is part of GNUnet.
# (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)
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
AC_PREREQ(2.61)
AC_INIT([GNUnet], [0.8.0c],[bug-gnunet@gnu.org])
AM_INIT_AUTOMAKE([GNUnet], [0.8.0c])
AC_CONFIG_HEADERS([config.h])

AH_TOP([#define _GNU_SOURCE  1])

# Checks for programs.
AC_CANONICAL_HOST
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_OBJC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([disable-static dlopen win32-dll])
AM_PATH_LIBLTDL([lt_dlopenext lt_dlsym], ,AC_MSG_ERROR([GNUnet needs libltdl]))
LT_LIB_DLLOAD
AC_SUBST(MKDIR_P)

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

# Use Linux interface name unless the OS has a different preference
DEFAULT_INTERFACE="\"eth0\""

# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(OSX,1,[This is an OS X system])
     CFLAGS="-no-cpp-precomp -fno-common $CFLAGS"
     AC_MSG_WARN([The VPN application cannot be compiled on your OS])
     build_target="macosx"
     DEFAULT_INTERFACE="\"en0\""
     LIBPREFIX=
     DLLDIR=lib
     QTLIBS="-L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     build_target="linux"
     LIBPREFIX=
     DLLDIR=lib
     AC_PATH_XTRA
     QTLIBS="-Wl,-rpath,$QTDIR/lib -L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     build_target="freebsd"
     LIBPREFIX=
     DLLDIR=lib
     QTLIBS="-Wl,-rpath,$QTDIR/lib -L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     LIBS=`echo $LIBS | sed -e "s/-ldl//"`
     build_target="openbsd"
     LIBPREFIX=
     DLLDIR=lib
     QTLIBS="-Wl,-rpath,$QTDIR/lib -L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
netbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
     LIBPREFIX=
     DLLDIR=lib
     QTLIBS="-Wl,-rpath,$QTDIR/lib -L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
*solaris*)
     AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
     AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
     AC_CHECK_LIB(resolv, res_init)
     AC_CHECK_LIB(rt, nanosleep)
     build_target="solaris"
     LIBPREFIX=
     DLLDIR=lib
     QTLIBS="-Wl,-rpath,$QTDIR/lib -L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
*arm-linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
     build_target="linux"
     LIBPREFIX=
     DLLDIR=lib
     QTLIBS="-Wl,-rpath,$QTDIR/lib -L$QTDIR/lib -lQtGui -lQtOpenGL -lQtCore $X_LIBS -lX11 -lXext -lXmu -lXt -lXi $X_EXTRA_LIBS -lGLU -lGL -lpthread"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtGui -I$QTDIR/include/QtCore -I$QTDIR/include/QtOpenGL $X_CFLAGS -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_SHARED"
     QTBIN="$QTDIR/bin"
     ;;
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="cygwin"
     LIBPREFIX=lib
     DLLDIR=bin
     AC_PROG_CXX
     QTLIBS="-L$QTDIR/lib -lopengl32 -lglu32 -lgdi32 -luser32 -lmingw32 -lqtmain -lQtOpenGL4 -lQtGui4 -lQtCore4 -mthreads -Wl,-enable-stdcall-fixup -Wl,-enable-auto-import -Wl,-enable-runtime-pseudo-reloc -Wl,-s -Wl,-s -Wl,-subsystem,windows"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtCore -I$QTDIR/include/QtGui -I$QTDIR/include/QtOpenGL -DUNICODE -DQT_LARGEFILE_SUPPORT -DQT_DLL -DQT_NO_DEBUG -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_THREAD_SUPPORT -DQT_NEEDS_QMAIN -frtti -fexceptions"
     QTBIN="$QTDIR/bin"
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_DEFINE_UNQUOTED(_WIN32,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined -Wl,--export-all-symbols"
     LIBS="$LIBS -lws2_32 -lplibc"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="mingw"
     AC_PROG_CXX
     LIBPREFIX=lib
     DLLDIR=bin
     QTLIBS="-L$QTDIR/lib -lopengl32 -lglu32 -lgdi32 -luser32 -lqtmain -lQtOpenGL4 -lQtGui4 -lQtCore4 -mthreads -Wl,-enable-stdcall-fixup -Wl,-enable-auto-import -Wl,-enable-runtime-pseudo-reloc -Wl,-s -Wl,-s -Wl,-subsystem,windows"
     QTINC="-I$QTDIR/include -I$QTDIR/include/QtCore -I$QTDIR/include/QtGui -I$QTDIR/include/QtOpenGL -DUNICODE -DQT_LARGEFILE_SUPPORT -DQT_DLL -DQT_NO_DEBUG -DQT_OPENGL_LIB -DQT_GUI_LIB -DQT_CORE_LIB -DQT_THREAD_SUPPORT -DQT_NEEDS_QMAIN -frtti -fexceptions"
     QTBIN="$QTDIR/bin"
     ;;
*)
     AC_MSG_RESULT(Unrecognised OS $host_os)
     AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
;;
esac
AC_DEFINE_UNQUOTED([GNUNET_DEFAULT_INTERFACE], $DEFAULT_INTERFACE, [This should be the default choice for the name of the first network interface])
AC_SUBST(DEFAULT_INTERFACE)

AC_MSG_CHECKING([for build target])
AM_CONDITIONAL(MACOSX,  test "$build_target" = "macosx")
AM_CONDITIONAL(CYGWIN,  test "$build_target" = "cygwin")
AM_CONDITIONAL(MINGW,   test "$build_target" = "mingw")
AM_CONDITIONAL(SOLARIS, test "$build_target" = "solaris")
AM_CONDITIONAL(XFREEBSD, test "$build_target" = "freebsd")
AM_CONDITIONAL(OPENBSD, test "$build_target" = "openbsd")
AM_CONDITIONAL(LINUX, test "$build_target" = "linux")
AC_MSG_RESULT([$build_target])
AC_SUBST(build_target)
AM_CONDITIONAL([am__fastdepOBJC], false)
AC_UNALIGNED_64_ACCESS


CHECK_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"


# some other checks for standard libs
AC_SEARCH_LIBS([gethostbyname], [nsl ws2_32])
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, log)
AC_CHECK_LIB(c, getloadavg, AC_DEFINE(HAVE_GETLOADAVG,1,[getloadavg supported]))

# 'save' libs; only those libs found so far will be
# linked against _everywhere_.  For the others, we
# will be more selective!
SAVE_LIBS=$LIBS


# pthread_t is a struct since 11/2004
AC_CHECK_MEMBER(pthread_t.p, AC_DEFINE(HAVE_NEW_PTHREAD_T, 1,
  [Define if you have a post 11/2004 pthread library]), , [#include <pthread.h>])

AC_CHECK_FUNCS(pthread_equal)

# libgcrypt
gcrypt=0
AM_PATH_LIBGCRYPT(1.2.0, gcrypt=1)

if test $gcrypt = 0
then
  AC_MSG_ERROR([GNUnet needs libgcrypt])
fi


# libcurl
LIBCURL_CHECK_CONFIG(,7.15.4,,AC_MSG_ERROR([GNUnet requires libcurl >= 7.15.4]))
# restore LIBS
LIBS=$SAVE_LIBS

# libxml2
AM_PATH_XML2(,xml=1,xml=0)
AM_CONDITIONAL(HAVE_XML2, test x$xml = x1)
# restore LIBS
LIBS=$SAVE_LIBS

# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm],[kvm_open])
AC_CHECK_LIB([kstat],[kstat_open])

# test for libextractor
extractor=0
AC_MSG_CHECKING(for libextractor)
AC_ARG_WITH(extractor,
   [  --with-extractor=PFX    base of libextractor installation],
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
# restore LIBS
LIBS=$SAVE_LIBS


# Checks for standard header files.
AC_HEADER_DIRENT
AC_HEADER_STDC

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS([fcntl.h math.h errno.h ctype.h limits.h stdio.h stdlib.h string.h unistd.h stdarg.h signal.h locale.h sys/stat.h sys/types.h pthread.h],,AC_MSG_ERROR([Compiling GNUnet requires standard UNIX headers files]))

# Checks for headers that are only required on some systems or opional (and where we do NOT abort if they are not there)
AC_CHECK_HEADERS([langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/select.h sockLib.h sys/mman.h sys/msg.h sys/vfs.h arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h sys/file.h sys/resource.h iconv.h ifaddrs.h mach/mach.h stddef.h sys/timeb.h terminos.h])

# Check for GMP header (and abort if not present)
AC_CHECK_HEADERS([gmp.h],,AC_MSG_ERROR([Compiling GNUnet requires gmp.h (from the GNU MP library, libgmp)]))

# test for libgmp
gmp=0
AC_MSG_CHECKING(for libgmp)
AC_ARG_WITH(gmp,
   [  --with-gmp=PFX          base of libgmp installation],
   [AC_MSG_RESULT([$with_gmp])
    case $with_gmp in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(gmp.h,
          AC_CHECK_LIB([gmp], [__gmpz_add],
            gmp=1))
        ;;
      *)
        LDFLAGS="-L$with_gmp/lib $LDFLAGS"
        CPPFLAGS="-I$with_gmp/include $CPPFLAGS"
        AC_CHECK_HEADERS(gmp.h,
          AC_CHECK_LIB([gmp], [__gmpz_add],
            EXT_LIB_PATH="-L$with_gmp/lib $EXT_LIB_PATH"
            gmp=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-gmp not specified])
    AC_CHECK_HEADERS(gmp.h,
     AC_CHECK_LIB([gmp], [__gmpz_add],
      gmp=1))])
if test "$gmp" != 1
then
 AC_MSG_ERROR([GNUnet requires libgmp])
fi

SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS

# test for sqlite
sqlite=false
AC_MSG_CHECKING(for SQLite)
AC_ARG_WITH(sqlite,
  [  --with-sqlite=PFX       base of SQLite installation],
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

# test for postgres
postgres=false
AC_MSG_CHECKING(for postgres)
AC_ARG_WITH(postgres,
  [  --with-postgres=PFX       base of postgres installation],
  [AC_MSG_RESULT("$with_postgres")
   case $with_postgres in
   no)
     ;;
   yes)
    AC_CHECK_HEADERS(postgresql/libpq-fe.h,
     postgres=true)
     ;;
   *)
    LDFLAGS="-L$with_postgres/lib $LDFLAGS"
    CPPFLAGS="-I$with_postgres/include $CPPFLAGS"
    AC_CHECK_HEADERS(postgresql/libpq-fe.h,
     EXT_LIB_PATH="-L$with_postgres/lib $EXT_LIB_PATH"
     SQLITE_LDFLAGS="-L$with_postgres/lib"
     SQLITE_CPPFLAGS="-I$with_postgres/include"
     postgres=true)
    LDFLAGS=$SAVE_LDFLAGS
    CPPFLAGS=$SAVE_CPPFLAGS
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with-postgres not specified])
    AC_CHECK_HEADERS(postgresql/libpq-fe.h, postgres=true)])
AM_CONDITIONAL(HAVE_POSTGRES, test x$postgres = xtrue)
AC_SUBST(POSTGRES_CPPFLAGS)
AC_SUBST(POSTGRES_LDFLAGS)


# test for libz (maybe required for linking mysql)
zlib=1
AC_CHECK_LIB(z, compress,,zlib=0)
AM_CONDITIONAL(HAVE_ZLIB, test x$zlib = x1)
if test "$zlib" != 1
then
 AC_MSG_ERROR([GNUnet requires zlib])
fi

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
  [  --with-mysql=PFX        base of MySQL installation],
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
AC_ARG_ENABLE(mysql-version-check, [  --disable-mysql-version-check  do not check MySQL version],, enable_mysql_version_check=yes)
if test "$mysql" = "true" -a "x$enable_mysql_version_check" = "xyes"
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
AM_CONDITIONAL(HAVE_MYSQLE, test "0" = "1")
# restore LIBS
LIBS=$SAVE_LIBS
LDFLAGS=$SAVE_LDFLAGS
CPPFLAGS=$SAVE_CPPFLAGS

if test "$sqlite" = 0 -a "$mysql" = 0
then
 AC_MSG_ERROR([GNUnet requires SQLite or MySQL])
fi

# GNUnet Setup
dialog=0
LIBS="-lm $LIBS"
AC_CHECK_LIB([ncursesw],[wmove])
AC_MSG_CHECKING([for dialog 1.0-20051207])
AC_ARG_WITH(dialog,
   [  --with-dialog=PFX       base of dialog installation],
   [AC_MSG_RESULT([$with_dialog])
    case $with_dialog in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(dialog.h,
          AC_CHECK_LIB([dialog], [dlg_menu],
            dialog=1))
        ;;
      *)
        LDFLAGS="-L$with_dialog/lib $LDFLAGS"
        CPPFLAGS="-I$with_dialog/include $CPPFLAGS"
        AC_CHECK_HEADERS(dialog.h,
          AC_CHECK_LIB([dialog], [dlg_menu],
            EXT_LIB_PATH="-L$with_dialog/lib $EXT_LIB_PATH"
              dialog=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-dialog not specified])
    AC_CHECK_HEADERS(dialog.h,
      AC_CHECK_LIB([dialog], [dlg_menu],
          dialog=1))])

AM_CONDITIONAL(HAVE_DIALOG, test x$dialog = x1)
AC_DEFINE_UNQUOTED([HAVE_DIALOG], $dialog, [We have dialog])

cdialog=0
AC_ARG_WITH(cdialog,
   [  --with-cdialog=PFX      base of cdialog installation],
   [AC_MSG_RESULT([$with_cdialog])
    case $with_cdialog in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(cdialog/dialog.h,
          AC_CHECK_LIB([cdialog], [dlg_menu],
            cdialog=1))
        ;;
      *)
        LDFLAGS="-L$with_cdialog/lib $LDFLAGS"
        CPPFLAGS="-I$with_cdialog/include $CPPFLAGS"
        AC_CHECK_HEADERS(cdialog/dialog.h,
          AC_CHECK_LIB([cdialog], [dlg_menu],
            EXT_LIB_PATH="-L$with_cdialog/lib $EXT_LIB_PATH"
              cdialog=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-cdialog not specified])
    AC_CHECK_HEADERS(cdialog/dialog.h,
      AC_CHECK_LIB([cdialog], [dlg_menu],
          cdialog=1))])

AM_CONDITIONAL(HAVE_CDIALOG, test x$cdialog = x1)
AC_DEFINE_UNQUOTED([HAVE_CDIALOG], $cdialog, [We have cdialog])
# restore LIBS
LIBS=$SAVE_LIBS

# check for Qt 4
SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS
AC_LANG_PUSH([C++])
qt=0
AC_MSG_CHECKING(for Qt)
AC_ARG_WITH(qt,
   [  --with-qt=PFX           base of Qt installation],
   [AC_MSG_RESULT([$with_qt])
    case $with_qt in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS([Qt/qpixmap.h],
        	 AC_SEARCH_LIBS([_ZN7QPixmap12defaultDepthEv], [QtGui QtGui4],
              qt=1))
        ;;
      *)
        QTLIBS="$QTLIBS -L$with_qt/lib"
        LDFLAGS="$QTLIBS $LDFLAGS"
        QTINC="$QTINC -I$with_qt/include -I$with_qt/include/qt4"
        CPPFLAGS="$QTINC $CPPFLAGS"
        AC_CHECK_HEADERS([Qt/qpixmap.h],
        	 AC_SEARCH_LIBS([_ZN7QPixmap12defaultDepthEv], [QtGui QtGui4],
           EXT_LIB_PATH="-L$with_qt/lib $EXT_LIB_PATH"
           qt=1))
        ;;
    esac
   ],
  [AC_MSG_RESULT([--with-qt not specified])
    QTINC="$QTINC -I/usr/include -I/usr/include/qt4"
    QTLIBS="$QTLIBS -L/usr/lib"
    if ( pkg-config --help > /dev/null 2> /dev/null ) ; then
      if ( pkg-config --cflags QtGui && pkg-config --libs QtGui ) ; then
        QTINC=`pkg-config --cflags QtGui`
        QTLIBS=`pkg-config --libs QtGui`
      fi
    fi
    CPPFLAGS="$QTINC $CPPFLAGS"
    LDFLAGS="$QTLIBS $LDFLAGS"
    AC_CHECK_HEADERS([Qt/qpixmap.h],
       	  AC_SEARCH_LIBS([_ZN7QPixmap12defaultDepthEv], [QtGui QtGui4],
           EXT_LIB_PATH="-L$with_qt/lib $EXT_LIB_PATH"
              qt=1))])

LIBS="$LIBS $QTLIBS"
INCLUDES="$INCLUDES $QTINC"
PATH="$PATH:$QTBIN"
CXXFLAGS="$CXXFLAGS $QTINC"
AC_SUBST(QTINC)
AC_SUBST(QTLIBS)
# Verbatim from http://qtnode.net/wiki?title=Qt_with_autotools

# Now we check whether we can actually build a Qt app.
cat > myqt.h << EOF
#include <Qt/qobject.h>
class Test : public QObject
{
Q_OBJECT
public:
  Test() {}
  ~Test() {}
public slots:
  void receive() {}
signals:
  void send();
};
EOF

cat > myqt.cpp << EOF
#include "myqt.h"
#include <Qt/qapplication.h>
int main( int argc, char **argv )
{
  QApplication app( argc, argv );
  Test t;
  QObject::connect( &t, SIGNAL(send()), &t, SLOT(receive()) );
}
EOF

AC_MSG_CHECKING(does moc work?)
bnv_try_1="moc myqt.h -o moc_myqt.cpp"
AC_TRY_EVAL(bnv_try_1)
if test x"$ac_status" != x0; then
   AC_MSG_RESULT(moc doesn't work)
   qt=0
else
   AC_MSG_RESULT(yes)
fi
AC_MSG_CHECKING(can I compile moc_myqt.cpp?)
bnv_try_2="$CXX -c $CXXFLAGS -o moc_myqt.o moc_myqt.cpp"
AC_TRY_EVAL(bnv_try_2)
if test x"$ac_status" != x0; then
   AC_MSG_RESULT(couldn't compile moc_myqt.cpp)
   qt=0
else
   AC_MSG_RESULT(yes)
fi
AC_MSG_CHECKING(can I compile myqt.cpp?)
bnv_try_3="$CXX $QTINC -c $CXXFLAGS -o myqt.o myqt.cpp"
AC_TRY_EVAL(bnv_try_3)
if test x"$ac_status" != x0; then
   AC_MSG_RESULT(couldn't compile myqt.cpp)
   qt=0
else
   AC_MSG_RESULT(yes)
fi
AC_MSG_CHECKING(can I link against QT?)
nv_try_4="$CXX $LIBS -o myqt myqt.o moc_myqt.o"
AC_TRY_EVAL(bnv_try_4)
if test x"$ac_status" != x0; then
   AC_MSG_RESULT(couldn't link)
   qt=0
else
   AC_MSG_RESULT(yes)
fi


AC_MSG_CHECKING(for mkoctfile)
AC_TRY_EVAL(mkoctfile)
if test x"$ac_status" != x0; then
   AC_MSG_RESULT(mkoctfile is not in the path)
   qt=0
else
  AC_MSG_RESULT(yes)
fi
rm -f moc_myqt.cpp myqt.h myqt.cpp myqt.o myqt moc_myqt.o

AC_LANG_POP([C++])
# restore LIBS
LIBS=$SAVE_LIBS
LDFLAGS=$SAVE_LDFLAGS
CPPFLAGS=$SAVE_CPPFLAGS

# libmicrohttpd
lmhd=0
AC_MSG_CHECKING([for libmicrohttpd])
AC_ARG_WITH(microhttpd,
   [  --with-microhttpd=PFX   base of libmicrohttpd installation],
   [AC_MSG_RESULT([$with_microhttpd])
    case $with_microhttpd in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS([microhttpd.h],
	  AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
            AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
              lmhd=1),
	    [],[#include "src/include/platform.h"
                #include <microhttpd.h>]),,
            [#include "src/include/platform.h"])
        ;;
      *)
        LDFLAGS="-L$with_microhttpd/lib $LDFLAGS"
        CPPFLAGS="-I$with_microhttpd/include $CPPFLAGS"
        AC_CHECK_HEADERS(microhttpd.h,
	  AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
            AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
              EXT_LIB_PATH="-L$with_microhttpd/lib $EXT_LIB_PATH"
              lmhd=1),
	    [],[#include "src/include/platform.h"
                #include <microhttpd.h>]),,
            [#include "src/include/platform.h"])
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-microhttpd not specified])
    AC_CHECK_HEADERS([microhttpd.h],
      AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
        AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
          lmhd=1),
	[],[#include "src/include/platform.h"
            #include <microhttpd.h>]),,
       [#include "src/include/platform.h"])])
AM_CONDITIONAL(HAVE_MHD, test x$lmhd = x1)
AC_DEFINE_UNQUOTED([HAVE_MHD], $lmhd, [We have libmicrohttpd])
# restore LIBS
LIBS=$SAVE_LIBS

# libesmtp
esmtp=0
AC_MSG_CHECKING([for libesmtp])
AC_ARG_WITH(esmtp,
   [  --with-esmtp=PFX        base of libesmtp installation],
   [AC_MSG_RESULT([$with_esmtp])
    case $with_esmtp in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(libesmtp.h,
          AC_CHECK_LIB([esmtp], [smtp_start_session],
            esmtp=1))
        ;;
      *)
        LDFLAGS="-L$with_esmtp/lib $LDFLAGS"
        CPPFLAGS="-I$with_esmtp/include $CPPFLAGS"
        AC_CHECK_HEADERS(libesmtp.h,
          AC_CHECK_LIB([esmtp], [smtp_start_session],
            EXT_LIB_PATH="-L$with_esmtp/lib $EXT_LIB_PATH"
              esmtp=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-esmtp not specified])
    AC_CHECK_HEADERS(libesmtp.h,
      AC_CHECK_LIB([esmtp], [smtp_start_session],
          esmtp=1))])
AM_CONDITIONAL(HAVE_ESMTP, test x$esmtp = x1)
AC_DEFINE_UNQUOTED([HAVE_ESMTP], $esmtp, [We have libesmtp])
# restore LIBS
LIBS=$SAVE_LIBS

# c-ares (asynch dns)
c_ares=0
AC_MSG_CHECKING([for c-ares])
AC_ARG_WITH(c-ares,
   [  --with-c-ares=PFX       base of c-ares installation],
   [AC_MSG_RESULT([$with_c_ares])
    case $with_c_ares in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(ares.h,
          AC_CHECK_LIB([cares], [ares_process_fd],
            c_ares=1))
        ;;
      *)
        LDFLAGS="-L$with_c_ares/lib $LDFLAGS"
        CPPFLAGS="-I$with_c_ares/include $CPPFLAGS"
        AC_CHECK_HEADERS(ares.h,
          AC_CHECK_LIB([cares], [ares_process_fd],
            EXT_LIB_PATH="-L$with_c_ares/lib $EXT_LIB_PATH"
              c_ares=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-c-ares not specified])
    AC_CHECK_HEADERS(ares.h,
      AC_CHECK_LIB([cares], [ares_process_fd],
          c_ares=1))])

AM_CONDITIONAL(HAVE_C_ARES, test x$c_ares = x1)
AC_DEFINE_UNQUOTED([HAVE_C_ARES], $c_ares, [We have c-ares])
# restore LIBS
LIBS=$SAVE_LIBS

# GNU adns
adns=0
AC_MSG_CHECKING([for GNU adns])
AC_ARG_WITH(adns,
   [  --with-adns=PFX         base of GNU adns installation],
   [AC_MSG_RESULT([$with_adns])
    case $with_adns in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(adns.h,
          AC_CHECK_LIB([adns], [adns_init],
            adns=1))
        ;;
      *)
        LDFLAGS="-L$with_adns/lib $LDFLAGS"
        CPPFLAGS="-I$with_adns/include $CPPFLAGS"
        AC_CHECK_HEADERS(adns.h,
          AC_CHECK_LIB([adns], [adns_init],
            EXT_LIB_PATH="-L$with_adns/lib $EXT_LIB_PATH"
              adns=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-adns not specified])
    AC_CHECK_HEADERS(adns.h,
      AC_CHECK_LIB([adns], [adns_init],
          adns=1))])

AM_CONDITIONAL(HAVE_ADNS, test x$adns = x1)
AC_DEFINE_UNQUOTED([HAVE_ADNS], $adns, [We have GNU adns])
# restore LIBS
LIBS=$SAVE_LIBS


# check for gtk >= 2.6.0
AC_MSG_CHECKING(for gtk)
AM_PATH_GTK_2_0(2.6.0,without_gtk=false,without_gtk=true)
if test $without_gtk != true
then
 PKG_CHECK_MODULES(GNUNETGTK, libglade-2.0,  # libgnomeui-2.0 >= 1.110.0
 [
  AC_DEFINE_UNQUOTED([HAVE_GTK], 1, [We have GTK])
  AC_SUBST(GNUNETGTK_CFLAGS)
  AC_SUBST(GNUNETGTK_LIBS)
 ],
 [
  without_gtk=true
  AC_MSG_RESULT([libglade-2.0 not found])
 ])
fi
AM_CONDITIONAL(HAVE_GTK, test x$without_gtk != xtrue)

# check for gettext
AM_GNU_GETTEXT_VERSION([0.16.1])
AM_GNU_GETTEXT([external])

# check for iconv
AM_ICONV

# Checks for standard typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_HEADER_TIME
AC_HEADER_STAT
AC_HEADER_STDBOOL
AC_STRUCT_TM




# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_CHOWN

AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_CHECK_FUNCS([floor gethostname memmove rmdir strncasecmp strrchr strtol atoll dup2 fdatasync ftruncate gettimeofday memset mkdir mkfifo select socket strcasecmp strchr strdup strerror strstr clock_gettime getrusage rand uname setlocale getcwd mktime gmtime_r gmtime strlcpy strlcat ftruncate stat64 sbrk mmap mremap setrlimit gethostbyaddr initgroups getifaddrs freeifaddrs getnameinfo getaddrinfo inet_ntoa localtime_r nl_langinfo putenv realpath strndup gethostbyname2 gethostbyname])

# restore LIBS
LIBS=$SAVE_LIBS



# check for guile
guile=0
AC_MSG_CHECKING(for guile 1.8)
AC_ARG_WITH(guile,
   [  --with-guile=PFX        base of guile installation],
   [AC_MSG_RESULT([$with_guile])
    case $with_guile in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(libguile.h,
          AC_CHECK_LIB([guile], [scm_c_define_gsubr],
            guile=1, [],
            -lgmp $LIBLTDL))
        ;;
      *)
        LDFLAGS="-L$with_guile/lib $LDFLAGS"
        CPPFLAGS="-I$with_guile/include $CPPFLAGS"
        AC_CHECK_HEADERS(libguile.h,
          AC_CHECK_LIB([guile], [scm_c_define_gsubr],
            EXT_LIB_PATH="-L$with_guile/lib $EXT_LIB_PATH"
            guile=1, [],
            -lgmp $LIBLTDL))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-guile not specified])
    AC_CHECK_HEADERS(libguile.h,
     AC_CHECK_LIB([guile], [scm_c_define_gsubr],
      guile=1, [], -lgmp $LIBLTDL))])

if test "$guile" = 1
then
 AC_CHECK_LIB([guile], [scm_init_guile], [],
    	AC_MSG_ERROR([Guile doesn't provide scm_init_guile(). Please report to bug-gnunet@gnu.org]), -lgmp $LIBLTDL)
 AC_DEFINE_UNQUOTED([HAVE_GUILE], 1, [We have GUILE])
else
 AC_DEFINE_UNQUOTED([HAVE_GUILE], 0, [We do NOT have GUILE])
fi
AM_CONDITIONAL(HAVE_GUILE, test x$guile = x1)
# restore LIBS
LIBS=$SAVE_LIBS

if test "$qt" = 1
then
	AC_DEFINE(HAVE_QT, 1, [We have Qt])
fi
AM_CONDITIONAL(HAVE_QT, test x$qt != x0)

gn_user_home_dir="~/.gnunet"
AC_ARG_WITH(user-home-dir,
        AC_HELP_STRING(
                [--with-user-home-dir=DIR],
                [default user home directory (~/.gnunet)]),
        [gn_user_home_dir=$withval])
AC_SUBST(GN_USER_HOME_DIR, $gn_user_home_dir)
gn_daemon_home_dir="/var/lib/gnunet"
AC_ARG_WITH(daemon-home-dir,
        AC_HELP_STRING(
                [--with-daemon-home-dir=DIR],
                [default daemon home directory (/var/lib/gnunet)]),
        [gn_daemon_home_dir=$withval])
AC_SUBST(GN_DAEMON_HOME_DIR, $gn_daemon_home_dir)
gn_daemon_config_dir="/etc"
AC_ARG_WITH(daemon-config-dir,
        AC_HELP_STRING(
                [--with-daemon-config-dir=DIR],
                [default daemon config directory (/etc)]),
        [gn_daemon_config_dir=$withval])
AC_SUBST(GN_DAEMON_CONFIG_DIR, $gn_daemon_config_dir)
gn_daemon_pidfile="/var/run/gnunetd/pid"
AC_ARG_WITH(daemon-pidfile,
        AC_HELP_STRING(
                [--with-daemon-pidfile=FILE],
                [default daemon pidfile (/var/run/gnunetd/pid)]),
        [gn_daemon_pidfile=$withval])
AC_SUBST(GN_DAEMON_PIDFILE, $gn_daemon_pidfile)

GN_INTLINCL=""
GN_LIBINTL="$LTLIBINTL"
AC_ARG_ENABLE(framework, [  --enable-framework      enable Mac OS X framework build helpers],enable_framework_build=$enableval)
AM_CONDITIONAL(WANT_FRAMEWORK, test x$enable_framework_build = xyes)
if test x$enable_framework_build = xyes
then
  AC_DEFINE([FRAMEWORK_BUILD], 1, [Build a Mac OS X Framework])
  GN_INTLINCL='-I$(top_srcdir)/src/intlemu'
  GN_LIBINTL='$(top_builddir)/src/intlemu/libintlemu.la -framework CoreFoundation'
  AC_LIB_APPENDTOVAR([CPPFLAGS], [$GN_INTLINCL]) 
fi

GN_LIB_LDFLAGS="-export-dynamic -no-undefined"
GN_PLUGIN_LDFLAGS="-export-dynamic -avoid-version -module -no-undefined"
dnl TODO insert a proper check here
AC_CACHE_CHECK([whether -export-symbols-regex works],
 gn_cv_export_symbols_regex_works, 
 [
  case "$host_os" in
  mingw*) gn_cv_export_symbols_regex_works=no;;
  *) gn_cv_export_symbols_regex_works=yes;;
  esac
 ])
if test "x$gn_cv_export_symbols_regex_works" = "xyes"
then
 GN_LIB_LDFLAGS="$GN_LIB_LDFLAGS -export-symbols-regex \"GNUNET_@<:@a-zA-Z0-9_@:>@*\""
 GN_PLUGIN_LDFLAGS="$GN_PLUGIN_LDFLAGS -export-symbols-regex \"@<:@a-zA-Z0-9_@:>@*\""
fi
AC_SUBST(GN_LIB_LDFLAGS)
AC_SUBST(GN_PLUGIN_LDFLAGS)
AC_SUBST(GN_INTLINCL)
AC_SUBST(GN_LIBINTL)

AC_SUBST(CPPFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LDFLAGS)
AC_SUBST(EXT_LIB_PATH)
AC_SUBST(EXT_LIBS)

AC_SUBST(LIBPREFIX)
AC_SUBST(DLLDIR)
AC_SUBST(EXT_LIB_PATH)


# gcov compilation
use_gcov=no
AC_ARG_ENABLE([coverage], AS_HELP_STRING([--enable-coverage],
                                        [Compile the library with code coverage support (default is NO)]),
                                        [use_gcov=yes], [use_gcov=no])
AM_CONDITIONAL([USE_COVERAGE], [test "x$use_gcov" = "xyes"])




AC_CONFIG_FILES([ po/Makefile.in m4/Makefile
Makefile
contrib/Makefile
contrib/config-client.scm
contrib/config-daemon.scm
contrib/macosx/Info.plist
doc/Makefile
doc/man/Makefile
src/Makefile
src/include/Makefile
src/include/gnunet_directories.h
src/intlemu/Makefile
src/applications/Makefile
src/applications/advertising/Makefile
src/applications/bootstrap_http/Makefile
src/applications/chat/Makefile
src/applications/chat/lib/Makefile
src/applications/chat/module/Makefile
src/applications/chat/tools/Makefile
src/applications/datastore/Makefile
src/applications/dht/Makefile
src/applications/dht/tools/Makefile
src/applications/dht/module/Makefile
src/applications/dstore_mysql/Makefile
src/applications/dstore_sqlite/Makefile
src/applications/fragmentation/Makefile
src/applications/fs/Makefile
src/applications/fs/collection/Makefile
src/applications/fs/ecrs/Makefile
src/applications/fs/fsui/Makefile
src/applications/fs/lib/Makefile
src/applications/fs/gap/Makefile
src/applications/fs/namespace/Makefile
src/applications/fs/uritrack/Makefile
src/applications/fs/tools/Makefile
src/applications/getoption/Makefile
src/applications/hostlist/Makefile
src/applications/identity/Makefile
src/applications/kvstore_sqlite/Makefile
src/applications/pingpong/Makefile
src/applications/rpc/Makefile
src/applications/session/Makefile
src/applications/sqstore_mysql/Makefile
src/applications/sqstore_postgres/Makefile
src/applications/sqstore_sqlite/Makefile
src/applications/state/Makefile
src/applications/stats/Makefile
src/applications/tbench/Makefile
src/applications/template/Makefile
src/applications/testing/Makefile
src/applications/topology_default/Makefile
src/applications/tracekit/Makefile
src/applications/traffic/Makefile
src/applications/transport/Makefile
src/applications/vpn/Makefile
src/libs/Makefile
src/libs/mysql/Makefile
src/setup/Makefile
src/setup/lib/Makefile
src/setup/gtk/Makefile
src/setup/qt/Makefile
src/setup/qt/pixmaps/Makefile
src/setup/cocoa/Makefile
src/setup/ncurses/Makefile
src/setup/text/Makefile
src/server/Makefile
src/transports/Makefile
src/transports/upnp/Makefile
src/util/Makefile
src/util/boot/Makefile
src/util/config/Makefile
src/util/containers/Makefile
src/util/cron/Makefile
src/util/crypto/Makefile
src/util/disk/Makefile
src/util/error/Makefile
src/util/getopt/Makefile
src/util/loggers/Makefile
src/util/network/Makefile
src/util/network_client/Makefile
src/util/os/Makefile
src/util/pseudonym/Makefile
src/util/string/Makefile
src/util/threads/Makefile
src/util/win/Makefile
])
AC_OUTPUT

# Finally: summary!

# warn user if mysql found but not used due to version
if test "$mysqlfail" = "true"
then
  AC_MSG_NOTICE([NOTICE: MySQL found, but too old. MySQL support will not be compiled.])
fi

# sqlite
if test "x$sqlite" = "x0"
then
  AC_MSG_NOTICE([NOTICE: sqlite not found.  sqLite support will not be compiled.])
fi


if test "$dialog" != 1 -a "$cdialog" != 1
then
 AC_MSG_NOTICE([NOTICE: curses based gnunet-setup frontends will not be installed.])
fi

if test "$lmhd" != 1
then
 AC_MSG_NOTICE([NOTICE: libmicrohttpd not found, http transport will not be installed.])
fi

if test "$esmtp" != 1
then
 AC_MSG_NOTICE([NOTICE: libesmtp not found, smtp transport will not be installed.])
fi

if test "$qt" != 1
then
 AC_MSG_NOTICE([NOTICE: qt not found, will not build gnunet-setup qt plugin.])
fi

if test "$ipv6" = "0"
then
  AC_MSG_NOTICE([NOTICE: IPv6 support will NOT be compiled.])
fi

AC_MSG_NOTICE([NOTICE: Database support is set to MySQL: $mysql, SQLite: $sqlite])

# guile
if test "x$guile" = "x0"
then
 AC_MSG_NOTICE([NOTICE: Guile not found, gnunet-download-manager will not be installed.])
 AC_MSG_NOTICE([WARNING: Guile not found, gnunet-setup will not be installed.])
fi

if test "$adns" != 1 -a "$c_ares" != 1
then
 AC_MSG_NOTICE([WARNING: Asynchronous resolver (adns or c-ares) not found, will use synchronous DNS resolution.])
fi

if test "$enable_framework_build" = "yes"
then
  AC_MSG_NOTICE([NOTICE: Mac OS X framework build enabled.])
fi

AC_MSG_NOTICE([********************************************
You can build GNUnet with
	make install
now. After that, run
	gnunet-setup -d wizard-gtk
(on graphical systems with GTK) or
	gnunet-setup -d wizard-curses
(on text-based systems with curses) in order to make important configuration
settings. If neither works for you, you can find a template configuration
file in the contrib/ subdirectory. Copy it to /etc/gnunetd.conf and modify it
using your favourite text editor.
********************************************])
