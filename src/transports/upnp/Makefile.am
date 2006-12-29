INCLUDES = -I$(top_srcdir)/src/include

AM_CFLAGS = $(GTK_CFLAGS)

plugindir = $(libdir)/GNUnet

LIBS = @LIBINTL@ @LIBS@

plugin_LTLIBRARIES = \
  libgnunetmodule_upnp.la

libgnunetmodule_upnp_la_SOURCES = \
 error.c error.h \
 init.c \
 ip.c ip.h \
 util.c util.h \
 xmlnode.c xmlnode.h \
 upnp.c upnp.h 

libgnunetmodule_upnp_la_LDFLAGS = \
 -export-dynamic -avoid-version -module
libgnunetmodule_upnp_la_CFLAGS = \
 -I$(top_scrdir)/include \
 @LIBCURL_CPPFLAGS@ @XML_CPPFLAGS@ @GNUNETGTK_CFLAGS@ @GTK_CFLAGS@
libgnunetmodule_upnp_la_LIBADD = \
 @GTK_LIBS@ @EXT_LIB_PATH@ @EXT_LIBS@ \
 @GNUNETGTK_LIBS@ @XML_LIBS@ @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
 upnptest 

TESTS = $(check_PROGRAMS)

upnptest_SOURCES = \
 upnptest.c 
upnptest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la 


