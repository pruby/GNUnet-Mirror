INCLUDES = -I$(top_srcdir)/src/include 

lib_LTLIBRARIES = \
  libgnunetdht_api.la 

bin_PROGRAMS = \
  gnunet-dht-join \
  gnunet-dht-query 

libgnunetdht_api_la_SOURCES = \
  dht_api.c 
libgnunetdht_api_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la


gnunet_dht_join_SOURCES = \
  dht-join.c
gnunet_dht_join_LDADD = \
  $(top_builddir)/src/applications/dht/module/libgnunetmodule_dht_datastore_memory.la \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/libgnunetutil.la


gnunet_dht_query_SOURCES = \
  dht-query.c
gnunet_dht_query_LDADD =  \
  $(top_builddir)/src/applications/dht/tools/libgnunetdht_api.la \
  $(top_builddir)/src/util/libgnunetutil.la

