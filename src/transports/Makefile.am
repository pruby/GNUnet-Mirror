INCLUDES = -I$(top_srcdir)/src/include

EXTRA_DIST = common.c common.h test.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

plugindir = $(libdir)/GNUnet

if HAVE_XML2
  build_upnp=upnp
endif

if HAVE_MHD
  httptransport = libgnunettransport_http.la
  httptest = test_http testrepeat_http
endif

if !MINGW
if HAVE_ESMTP
  smtptransport = libgnunettransport_smtp.la
endif
endif

SUBDIRS = . $(build_upnp)

lib_LTLIBRARIES = \
  libgnunetip.la

check_PROGRAMS = $(httptest) \
  test_udp \
  test_tcp \
  testrepeat_udp \
  testrepeat_tcp 

TESTS = $(check_PROGRAMS)

libgnunetip_la_SOURCES = \
  ip.c ip.h
libgnunetip_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS)
libgnunetip_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)

plugin_LTLIBRARIES = \
 libgnunettransport_tcp.la \
 libgnunettransport_udp.la \
 libgnunettransport_nat.la \
 $(httptransport) $(smtptransport)

libgnunettransport_smtp_la_SOURCES = smtp.c
libgnunettransport_smtp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lesmtp \
 $(GN_LIBINTL)
libgnunettransport_smtp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunettransport_http_la_SOURCES = http.c
libgnunettransport_http_la_LIBADD = \
 -lmicrohttpd @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la \
 $(GN_LIBINTL)
libgnunettransport_http_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) 
libgnunettransport_http_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@

libgnunettransport_tcp_la_SOURCES = tcp.c
libgnunettransport_tcp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la \
 $(GN_LIBINTL)
libgnunettransport_tcp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunettransport_nat_la_SOURCES = nat.c
libgnunettransport_nat_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la 
libgnunettransport_nat_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunettransport_udp_la_SOURCES = udp.c
libgnunettransport_udp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la \
 $(GN_LIBINTL)
libgnunettransport_udp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)




test_udp_SOURCES = \
 test.c 
test_udp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

test_tcp_SOURCES = \
 test.c 
test_tcp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

test_http_SOURCES = \
 test.c 
test_http_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

testrepeat_tcp_SOURCES = \
 test_repeat.c 
testrepeat_tcp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

testrepeat_udp_SOURCES = \
 test_repeat.c 
testrepeat_udp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

testrepeat_http_SOURCES = \
 test_repeat.c 
testrepeat_http_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

