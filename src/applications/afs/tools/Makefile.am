INCLUDES = -I$(top_srcdir)/src/include

LDADD = \
  $(top_builddir)/src/applications/afs/esed2/libgnunetmodule__afs_esed2.la \
  $(top_builddir)/src/util/libgnunetutil.la

bin_PROGRAMS = \
  gnunet-insert \
  gnunet-search \
  gnunet-download \
  gnunet-delete \
  gnunet-directory \
  gnunet-pseudonym 


gnunet_insert_SOURCES = \
  gnunet-insert.c 	

gnunet_delete_SOURCES = \
  gnunet-delete.c 	

gnunet_directory_SOURCES = \
  gnunet-directory.c

gnunet_pseudonym_SOURCES = \
  gnunet-pseudonym.c

gnunet_search_SOURCES = \
  gnunet-search.c

gnunet_download_SOURCES = \
  gnunet-download.c 
