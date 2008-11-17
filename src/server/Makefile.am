INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libgnunetcore.la

bin_PROGRAMS = \
 gnunetd \
 gnunet-peer-info \
 gnunet-transport-check \
 gnunet-update 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif


libgnunetcore_la_SOURCES = \
 connection.c connection.h \
 core.c \
 handler.c handler.h \
 tcpserver.c tcpserver.h \
 startup.c startup.h \
 version.c version.h
libgnunetcore_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunetcore_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS)

gnunetd_SOURCES = \
 gnunetd.c 
gnunetd_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la


gnunet_update_SOURCES = \
 gnunet-update.c 
gnunet_update_LDADD = \
 $(top_builddir)/src/server/libgnunetcore.la

gnunet_peer_info_SOURCES = \
 gnunet-peer-info.c 
gnunet_peer_info_LDADD  = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/server/libgnunetcore.la

gnunet_transport_check_SOURCES = \
 gnunet-transport-check.c 
gnunet_transport_check_LDADD  = \
 $(top_builddir)/src/server/libgnunetcore.la

