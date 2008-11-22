INCLUDES = -I$(top_srcdir)/src/include


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetgetoption_api.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_getoption.la 


libgnunetgetoption_api_la_SOURCES = \
  clientapi.c 
libgnunetgetoption_api_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetgetoption_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

libgnunetmodule_getoption_la_SOURCES = \
  getoption.c getoption.h
libgnunetmodule_getoption_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_getoption_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
