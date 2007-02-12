INCLUDES = -I$(top_srcdir)/src/include

EXTRA_DIST = tcp_helper.c udp_helper.c

plugindir = $(libdir)/GNUnet

if HAVE_IPV6
 v6transports = \
  libgnunettransport_tcp6.la \
  libgnunettransport_udp6.la 
 v6ip = \
  libip6.la
endif
if HAVE_XML2
  build_upnp=upnp
endif

if HAVE_MHD
  httptransport = libgnunettransport_http.la
endif

SUBDIRS = $(build_upnp) .

noinst_LTLIBRARIES = \
  $(v6ip) \
  libip.la

if !MINGW
# smtptransport = libgnunettransport_smtp.la
endif

libip_la_SOURCES = \
  ip.c ip.h

libip6_la_SOURCES = \
  ip6.c ip6.h

plugin_LTLIBRARIES = \
 libgnunettransport_tcp.la \
 libgnunettransport_udp.la \
 libgnunettransport_tcp_old.la \
 libgnunettransport_nat.la \
 $(v6transports) $(httptransport)

#libgnunettransport_smtp_la_SOURCES = smtp.c
#libgnunettransport_smtp_la_LIBADD = \
# $(top_builddir)/src/util/libgnunetutil.la -lesmtp
#libgnunettransport_smtp_la_LDFLAGS = \
# -export-dynamic -avoid-version -module 

libgnunettransport_http_la_SOURCES = http.c
libgnunettransport_http_la_LIBADD = \
 -lmicrohttpd @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la \
 libip.la
libgnunettransport_http_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 
libgnunettransport_http_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@

libgnunettransport_tcp_la_SOURCES = tcp.c
libgnunettransport_tcp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libip.la
libgnunettransport_tcp_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_nat_la_SOURCES = nat.c
libgnunettransport_nat_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunettransport_nat_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_udp_la_SOURCES = udp.c
libgnunettransport_udp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libip.la
libgnunettransport_udp_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_tcp6_la_SOURCES = tcp6.c
libgnunettransport_tcp6_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libip6.la
libgnunettransport_tcp6_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_udp6_la_SOURCES = udp6.c
libgnunettransport_udp6_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libip6.la
libgnunettransport_udp6_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 



libgnunettransport_tcp_old_la_SOURCES = tcp_old.c
libgnunettransport_tcp_old_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libip.la
libgnunettransport_tcp_old_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 


