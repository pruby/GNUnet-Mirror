INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libnetwork.la

libnetwork_la_SOURCES = \
 dns.c \
 endian.c network.h \
 io.c \
 ip.c \
 ipcheck.c \
 select.c 


check_PROGRAMS = \
 selecttest 

TESTS = $(check_PROGRAMS)

selecttest_SOURCES = \
 selecttest.c 
selecttest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la


