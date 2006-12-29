SUBDIRS = $(WINSUBDIRS) $(CYGSUBDIRS) \
  error string config \
  getopt disk threads \
  os network . \
  config_impl cron crypto \
  containers loggers network_client \
  boot

INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

AM_CFLAGS = \
  -DPLUGIN_PATH="\"${plugindir}\"" -DPREFIX_PATH="\"${prefix}\""

# GNU Gettext support
LIBS = @LIBINTL@ @LIBICONV@ @LIBS@

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
 config/libconfig.la \
 disk/libdisk.la \
 error/liberror.la \
 getopt/libgetopt.la \
 string/libstring.la \
 network/libnetwork.la \
 os/libos.la \
 threads/libthreads.la

libgnunetutil_la_SOURCES = libgnunetutil.c

EXTRA_DIST = \
  check.conf

libgnunetutil_la_LDFLAGS = \
 -export-dynamic $(LIBLTDL) $(LIBGCRYPT_LIBS) $(SOLFLAGS) $(WINFLAGS) $(LIBS) -lgmp $(DLFLAG) \
 -version-info 1:0:0

