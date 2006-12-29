INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

# GNU Gettext support
LIBS = @LIBINTL@ @LIBS@

lib_LTLIBRARIES = \
  libgnunetupnp.la

libgnunetupnp_la_SOURCES = \
 error.c error.h \
 init.c \
 ip.c ip.h \
 util.c util.h \
 xmlnode.c xmlnode.h \
 upnp.c upnp.h 

libgnunetupnp_la_LDFLAGS = \
 $(GTK_LIBS) @EXT_LIB_PATH@ @EXT_LIBS@ @LIBCURL@ \
 -export-dynamic \
 -version-info 0:0:0

# FIXME: detect libxml2 path properly!
libgnunetupnp_la_CFLAGS =  @LIBCURL_CPPFLAGS@ \
 -I$(top_scrdir)/include \
 -I/usr/include/libxml2 \
 @GNUNETGTK_CFLAGS@ \
 @GTK_CFLAGS@ 


libgnunetupnp_la_LIBADD = \
 @GTK_LIBS@ @EXT_LIB_PATH@ @EXT_LIBS@ \
 @GNUNETGTK_LIBS@ \
  $(INTLLIBS) \
  -lgthread-2.0 \
 $(top_builddir)/src/util/libgnunetutil.la 


noinst_PROGRAMS = \
 upnpdemo

upnpdemo_SOURCES = \
 upnpdemo.c 
upnpdemo_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/transports/upnp/libgnunetupnp.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la 



check_PROGRAMS = \
 upnptest 

TESTS = $(check_PROGRAMS)

upnptest_SOURCES = \
 upnptest.c 
upnptest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/transports/upnp/libgnunetupnp.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la 


