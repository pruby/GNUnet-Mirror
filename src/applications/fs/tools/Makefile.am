INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
  $(top_builddir)/src/applications/fs/fsui/libgnunetfsui.la \
  $(top_builddir)/src/applications/fs/ecrs/libgnunetecrs.la \
  $(top_builddir)/src/util/libgnunetutil.la

bin_PROGRAMS = \
  gnunet-directory \
  gnunet-pseudonym \
  gnunet-search \
  gnunet-insert \
  gnunet-download \
  gnunet-unindex



gnunet_insert_SOURCES = \
  gnunet-insert.c 	

gnunet_unindex_SOURCES = \
  gnunet-unindex.c 	

gnunet_directory_SOURCES = \
  gnunet-directory.c

gnunet_pseudonym_SOURCES = \
  gnunet-pseudonym.c

gnunet_search_SOURCES = \
  gnunet-search.c

gnunet_download_SOURCES = \
  gnunet-download.c 
