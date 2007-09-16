INCLUDES = -I$(top_srcdir)/src/include

EXTRA_DIST = tcp_helper.c udp_helper.c test.conf

plugindir = $(libdir)/GNUnet

if HAVE_IPV6
 v6transports = \
  libgnunettransport_tcp6.la \
  libgnunettransport_udp6.la 
 v6ip = \
  libgnunetip6.la
endif
if HAVE_XML2
  build_upnp=upnp
endif

if HAVE_MHD
  httptransport = libgnunettransport_http.la
endif

SUBDIRS = . $(build_upnp)

noinst_LTLIBRARIES = \
  $(v6ip) 

lib_LTLIBRARIES = \
  libgnunetip.la

check_PROGRAMS = \
  test_udp \
  test_tcp \
  test_http \
  testrepeat_udp \
  testrepeat_tcp \
  testrepeat_http 

TESTS = $(check_PROGRAMS)


if !MINGW
# smtptransport = libgnunettransport_smtp.la
endif

libgnunetip_la_SOURCES = \
  ip.c ip.h
libgnunetip_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la

libgnunetip6_la_SOURCES = \
  ip6.c ip6.h

plugin_LTLIBRARIES = \
 libgnunettransport_tcp.la \
 libgnunettransport_udp.la \
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
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 libgnunetip.la
libgnunettransport_http_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 
libgnunettransport_http_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@

libgnunettransport_tcp_la_SOURCES = tcp.c
libgnunettransport_tcp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la
libgnunettransport_tcp_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_nat_la_SOURCES = nat.c
libgnunettransport_nat_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la 
libgnunettransport_nat_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_udp_la_SOURCES = udp.c
libgnunettransport_udp_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la
libgnunettransport_udp_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_tcp6_la_SOURCES = tcp6.c
libgnunettransport_tcp6_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la \
 libgnunetip6.la
libgnunettransport_tcp6_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 

libgnunettransport_udp6_la_SOURCES = udp6.c
libgnunettransport_udp6_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetip.la \
 libgnunetip6.la
libgnunettransport_udp6_la_LDFLAGS = \
 -export-dynamic -avoid-version -module 





test_udp_SOURCES = \
 test.c 
test_udp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la

test_tcp_SOURCES = \
 test.c 
test_tcp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la

test_http_SOURCES = \
 test.c 
test_http_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la

testrepeat_tcp_SOURCES = \
 test_repeat.c 
testrepeat_tcp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la

testrepeat_udp_SOURCES = \
 test_repeat.c 
testrepeat_udp_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la

testrepeat_http_SOURCES = \
 test_repeat.c 
testrepeat_http_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la \
 $(top_builddir)/src/util/cron/libgnunetutil_cron.la \
 $(top_builddir)/src/util/boot/libgnunetutil_boot.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la

