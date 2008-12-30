SUBDIRS = $(WINSUBDIRS) $(CYGSUBDIRS) \
  boot \
  config \
  containers \
  cron \
  crypto \
  disk \
  error \
  getopt \
  loggers \
  network \
  network_client \
  os \
  string \
  threads \
  pseudonym \
  .

INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

AM_CFLAGS = \
  -DPLUGIN_PATH="\"${plugindir}\"" -DPREFIX_PATH="\"${prefix}\""

if SOLARIS
 SOLLIBADD = -lrt
endif

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -liconv -lstdc++ -lcomdlg32 -lgdi32
 WINSUBDIRS = win
 WINLIBADD = $(top_builddir)/src/util/win/libwin.la 
endif

if CYGWIN
 CYGSUBDIRS = win
 CYGLIBADD = $(top_builddir)/src/util/win/libwin.la 
endif

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetutil.la

libgnunetutil_la_SOURCES = libgnunetutil.c
libgnunetutil_la_LIBADD = \
  boot/libboot.la \
  config/libconfig.la \
  containers/libcontainers.la \
  cron/libcron.la \
  crypto/libcrypto.la \
  disk/libdisk.la \
  error/liberror.la \
  getopt/libgetopt.la \
  loggers/libloggers.la \
  string/libstring.la \
  network/libnetwork.la \
  network_client/libnetwork_client.la \
  os/libos.la \
  pseudonym/libpseudonym.la \
  threads/libthreads.la \
  $(GCLIBADD) $(CYGLIBADD) $(WINLIBADD) \
  $(LIBGCRYPT_LIBS) \
  -lgmp \
  $(GN_LIBINTL) \
  $(LTLIBICONV) \
  $(LIBLTDL) \
  $(LIBADD_DL) \
  $(SOLLIBADD)
libgnunetutil_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 3:0:0

EXTRA_DIST = \
  check.conf

