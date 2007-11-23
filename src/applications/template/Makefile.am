INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

# change to bin_PROGRAMS for real apps
noinst_PROGRAMS = \
  gnunet-template

plugin_LTLIBRARIES = \
  libgnunetmodule_template.la


gnunet_template_SOURCES = \
  gnunet-template.c 	

libgnunetmodule_template_la_SOURCES = \
  template.c 
libgnunetmodule_template_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(top_builddir)/src/util/libgnunetutil.la 



