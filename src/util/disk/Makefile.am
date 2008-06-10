INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libdisk.la

libdisk_la_SOURCES = \
  storage.c \
  filenames.c 

check_PROGRAMS = \
 storagetest 

TESTS = $(check_PROGRAMS)

storagetest_SOURCES = \
 storagetest.c
storagetest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

