INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet



bin_PROGRAMS = \
  gnunet-vpn

plugin_LTLIBRARIES = \
  libgnunetmodule_vpn.la


gnunet_vpn_SOURCES = \
  gnunet-vpn.c 	
gnunet_vpn_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetmodule_vpn_la_SOURCES = \
  vpn.c 
libgnunetmodule_vpn_la_LDFLAGS = \
  -export-dynamic -avoid-version -module
libgnunetmodule_vpn_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
