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
gnunet_vpn_LDADD = \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/network_client/libgnunetutil_network_client.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetmodule_vpn_la_SOURCES = \
  vpn.c 
libgnunetmodule_vpn_la_LDFLAGS = \
  -export-dynamic -avoid-version -module \
  $(LDADD)



