INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_session.la 

libgnunetmodule_session_la_SOURCES = \
  connect.c 
libgnunetmodule_session_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetmodule_session_la_LDFLAGS = \
  -export-dynamic -avoid-version -module



check_PROGRAMS = \
  sessiontest 

TESTS = $(check_PROGRAMS)

sessiontest_SOURCES = \
  sessiontest.c 
sessiontest_LDADD = \
  $(top_builddir)/src/applications/stats/libgnunetstats_api.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  peer1.conf \
  peer2.conf \
  peer1/.hostkey \
  peer2/.hostkey \
  peer1/data/hosts/BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77FOPDA8F1VIKESLSNBO.6 \
  peer2/data/hosts/D73MOVC9CA0QMTMG4Q2QBQL8D8FVOLBN41MIQHN0GM7IMAS2VKU46NU69OHQEE19BCQMDFOMFT2H6PJ5KF29DJFLUUCO0CFGK0E56R0.6
