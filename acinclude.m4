# See: http://gcc.gnu.org/ml/gcc/2000-05/msg01141.html
AC_DEFUN([CHECK_PTHREAD],
[
	AC_CHECK_LIB(pthread,pthread_create,
	[
		PTHREAD_CPPFLAGS=
		PTHREAD_LDFLAGS=
		PTHREAD_LIBS=-lpthread
	],[
		AC_MSG_CHECKING(if compiler supports -pthread)
		save_CPPFLAGS="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS -pthread"
		AC_TRY_LINK(
		[
			#include <pthread.h>
		],[
			pthread_create(0,0,0,0);
		],[
			AC_MSG_RESULT(yes)
			PTHREAD_CPPFLAGS=-pthread
			PTHREAD_LDFLAGS=-pthread
			PTHREAD_LIBS=
		],[
			AC_MSG_RESULT(no)
			AC_MSG_CHECKING(if compiler supports -pthreads)
			save_CPPFLAGS="$CPPFLAGS"
			CPPFLAGS="$save_CPPFLAGS -pthreads"
			AC_TRY_LINK(
			[
				#include <pthread.h>
			],[
				pthread_create(0,0,0,0);
			],[
				AC_MSG_RESULT(yes)
				PTHREAD_CPPFLAGS=-pthreads
				PTHREAD_LDFLAGS=-pthreads
				PTHREAD_LIBS=
			],[
				AC_MSG_RESULT(no)
				AC_MSG_CHECKING(if compiler supports -threads)
				save_CPPFLAGS="$CPPFLAGS"
				CPPFLAGS="$save_CPPFLAGS -threads"
				AC_TRY_LINK(
				[
					#include <pthread.h>
				],[
					pthread_create(0,0,0,0);
				],[
					AC_MSG_RESULT(yes)
					PTHREAD_CPPFLAGS=-threads
					PTHREAD_LDFLAGS=-threads
					PTHREAD_LIBS=
				],[
					AC_MSG_ERROR([Your system is not supporting pthreads!])
				])
			])
		])
		CPPFLAGS="$save_CPPFLAGS"
	])
])

# OpenSSL check
AC_DEFUN([AM_GNUNET_SSL_VERSION], [
  AC_PATH_PROG(SSL_CONF, openssl, no)
  if test "x$SSL_CONF" = "xno"; then
    AC_MSG_ERROR(GNUnet requires a working installation of OpenSSL or libgcrypt)
  else
    ssl_major_version=`$SSL_CONF version | \
         $ac_cv_prog_AWK '{print $[2]}' | \
         $ac_cv_prog_AWK -F. '{print $[1]}'`
    ssl_minor_version=`$SSL_CONF version | \
        $ac_cv_prog_AWK '{print $[2]}' | \
        $ac_cv_prog_AWK -F. '{print $[2]}'`
    ssl_micro_version=`$SSL_CONF version | \
        $ac_cv_prog_AWK '{print $[2]}' | \
        $ac_cv_prog_AWK -F. '{print $[3]}' | \
        sed 's/[[^0-9]]//g'`
    AC_DEFINE_UNQUOTED(SSL_MAJOR, $ssl_major_version, [OpenSSL Major Version])
    AC_DEFINE_UNQUOTED(SSL_MINOR, $ssl_minor_version, [OpenSSL Minor Version])
    AC_DEFINE_UNQUOTED(SSL_MICRO, $ssl_micro_version, [OpenSSL Micro Version])
  fi
])





