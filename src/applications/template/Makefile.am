INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
plugindir = $(libdir)/GNUnet

# change to bin_PROGRAMS for real apps
noinst_PROGRAMS = \
  gnunet-template

plugin_LTLIBRARIES = \
  libgnunetmodule_template.la


gnunet_template_SOURCES = \
  gnunet-template.c 	
gnunet_template_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


libgnunetmodule_template_la_SOURCES = \
  template.c 
libgnunetmodule_template_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
