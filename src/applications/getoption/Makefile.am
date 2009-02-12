INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetgetoptionapi.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_getoption.la 


libgnunetgetoptionapi_la_SOURCES = \
  clientapi.c 
libgnunetgetoptionapi_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetgetoptionapi_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

libgnunetmodule_getoption_la_SOURCES = \
  getoption.c getoption.h
libgnunetmodule_getoption_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_getoption_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
