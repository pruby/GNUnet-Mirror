INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

lib_LTLIBRARIES = \
  libgnunetgetoption_api.la 

plugin_LTLIBRARIES = \
  libgnunetmodule_getoption.la 


libgnunetgetoption_api_la_SOURCES = \
  clientapi.c 
libgnunetgetoption_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

libgnunetmodule_getoption_la_SOURCES = \
  getoption.c getoption.h
libgnunetmodule_getoption_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_getoption_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
