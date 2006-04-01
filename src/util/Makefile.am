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

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS)

libgnunetutil_la_LIBADD = $(GCLIBADD) $(CYGLIBADD) $(WINLIBADD)
SUBDIRS = $(WINSUBDIRS) $(CYGSUBDIRS) .

EXTRA_DIST = \
  testconfig.conf \
  check.conf

libgnunetutil_la_LDFLAGS = \
 -export-dynamic $(LIBLTDL) $(LIBGCRYPT_LIBS) $(SOLFLAGS) $(WINFLAGS) $(LIBS) -lgmp $(DLFLAG) \
 -version-info 1:0:0

libgnunetutil_la_SOURCES = \
 bloomfilter.c \
 checksum.c \
 configuration.c \
 cron.c \
 daemon.c \
 dso.c \
 getopt.c \
 hashing.c \
 hashtable.c \
 hostkey_gcrypt.c \
 initialize.c \
 io.c \
 ipcheck.c \
 kblockkey.c \
 locking_gcrypt.c \
 locking_gcrypt.h \
 logging.c \
 osconfig.c \
 printhelp.c \
 port.c \
 random.c \
 semaphore.c \
 shutdown.c \
 state.c \
 statuscalls.c \
 storage.c \
 string.c \
 symcipher_gcrypt.c \
 tcp_return.c \
 tcpio.c \
 timer.c \
 vector.c \
 xmalloc.c 

################################
# TESTCASES 
################################

check_PROGRAMS = \
 bloomtest \
 crctest \
 crontest \
 configtest \
 daemontest \
 hashtabletest \
 hashtest \
 hashingtest \
 hostkeytest \
 kblockkey_test \
 semaphoretest \
 shutdowntest \
 statetest \
 statuscallstest \
 storagetest \
 symciphertest \
 tcpiotest \
 timertest \
 vectortest \
 weakkeytest \
 xmalloctest 

TESTS = $(check_PROGRAMS)

xmalloctest_SOURCES = \
 xmalloctest.c 
xmalloctest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

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

hashtabletest_SOURCES = \
 hashtabletest.c
hashtabletest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

hashingtest_SOURCES = \
 hashingtest.c
hashingtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

tcpiotest_SOURCES = \
 tcpiotest.c
tcpiotest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

vectortest_SOURCES = \
 vectortest.c
vectortest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

crctest_SOURCES = \
 crctest.c
crctest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

kblockkey_test_SOURCES = \
 kblockkey_test.c
kblockkey_test_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

configtest_SOURCES = \
 configtest.c
configtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

crontest_SOURCES = \
 crontest.c
crontest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

hostkeytest_SOURCES = \
 hostkeytest.c
hostkeytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

hashtest_SOURCES = \
 hashtest.c
hashtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

storagetest_SOURCES = \
 storagetest.c
storagetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

statuscallstest_SOURCES = \
 statuscallstest.c
statuscallstest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

symciphertest_SOURCES = \
 symciphertest.c
symciphertest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

semaphoretest_SOURCES = \
 semaphoretest.c
semaphoretest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

weakkeytest_SOURCES = \
 weakkeytest.c
weakkeytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

bloomtest_SOURCES = \
 bloomtest.c
bloomtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
