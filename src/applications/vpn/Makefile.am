if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif
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
  cs.c cs.h \
  helper.c helper.h \
  p2p.c p2p.h \
  vpn.c vpn.h
libgnunetmodule_vpn_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunetmodule_vpn_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
