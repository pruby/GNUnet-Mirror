SUBDIRS = $(WINSUBDIRS) $(CYGSUBDIRS) error string config getopt . config_impl loggers crypto containers

INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

AM_CFLAGS = \
  -DPLUGIN_PATH="\"${plugindir}\"" -DPREFIX_PATH="\"${prefix}\""

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

if SOLARIS
 SOLFLAGS = -lrt
endif

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -liconv -lstdc++ -lcomdlg32 -lgdi32
 WINSUBDIRS = win
 WINLIBADD = $(top_builddir)/src/util/win/libwin.la 
else
 DLFLAG = -ldl
endif

if XFREEBSD
 DLFLAG=
endif

if CYGWIN
 CYGSUBDIRS = win
 CYGLIBADD = $(top_builddir)/src/util/win/libwin.la 
endif

lib_LTLIBRARIES = libgnunetutil.la

libgnunetutil_la_LIBADD = $(GCLIBADD) $(CYGLIBADD) $(WINLIBADD) \
 error/liberror.la \
 config/libconfig.la \
 string/libstring.la \
 getopt/libgetopt.la

EXTRA_DIST = \
  testconfig.conf \
  check.conf

libgnunetutil_la_LDFLAGS = \
 -export-dynamic $(LIBLTDL) $(LIBGCRYPT_LIBS) $(SOLFLAGS) $(WINFLAGS) $(LIBS) -lgmp $(DLFLAG) \
 -version-info 1:0:0

libgnunetutil_la_SOURCES = \
 cron.c \
 daemon.c \
 dso.c \
 endian.c \
 getopt.c \
 initialize.c \
 io.c \
 ipcheck.c \
 osconfig.c \
 printhelp.c \
 port.c \
 semaphore.c \
 shutdown.c \
 state.c \
 statuscalls.c \
 storage.c \
 tcp_return.c \
 tcpio.c \
 timer.c

################################
# TESTCASES 
################################

check_PROGRAMS = \
 crontest \
 daemontest \
 semaphoretest \
 shutdowntest \
 statetest \
 statuscallstest \
 storagetest \
 tcpiotest \
 timertest 

TESTS = $(check_PROGRAMS)

daemontest_SOURCES = \
 daemontest.c 
daemontest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

statetest_SOURCES = \
 statetest.c
statetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

shutdowntest_SOURCES = \
 shutdowntest.c
shutdowntest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

timertest_SOURCES = \
 timertest.c
timertest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

tcpiotest_SOURCES = \
 tcpiotest.c
tcpiotest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

crontest_SOURCES = \
 crontest.c
crontest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

storagetest_SOURCES = \
 storagetest.c
storagetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

statuscallstest_SOURCES = \
 statuscallstest.c
statuscallstest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

semaphoretest_SOURCES = \
 semaphoretest.c
semaphoretest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


