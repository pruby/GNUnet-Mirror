INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libnetwork.la

if HAVE_ADNS
ADNS_LINK=-ladns
endif

libnetwork_la_SOURCES = \
 dns.c \
 endian.c network.h \
 io.c \
 ip.c \
 ipcheck.c \
 select.c 
libnetwork_la_LIBADD = $(ADNS_LINK)

check_PROGRAMS = \
 selecttest 

TESTS = $(check_PROGRAMS)

selecttest_SOURCES = \
 selecttest.c 
selecttest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la


