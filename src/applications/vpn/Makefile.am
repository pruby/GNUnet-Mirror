INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS = \
  gnunet-vpn

plugin_LTLIBRARIES = \
  libgnunetmodule_vpn.la


gnunet_vpn_SOURCES = \
  gnunet-vpn.c 	

libgnunetmodule_vpn_la_SOURCES = \
  vpn.c 
libgnunetmodule_vpn_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(LDADD)

