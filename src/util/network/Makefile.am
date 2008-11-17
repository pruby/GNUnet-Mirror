INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

noinst_LTLIBRARIES = \
  libnetwork.la
if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

if HAVE_C_ARES
 AR_LINK=-lcares
else
if HAVE_ADNS
 AR_LINK=-ladns
endif
endif

libnetwork_la_SOURCES = \
 dns.c \
 endian.c network.h \
 io.c \
 ip.c \
 ipcheck.c \
 select.c 
libnetwork_la_LIBADD = \
 $(AR_LINK)

check_PROGRAMS = \
 ipchecktest \
 selecttest 

TESTS = $(check_PROGRAMS)

selecttest_SOURCES = \
 selecttest.c 
selecttest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la



ipchecktest_SOURCES = \
 ipchecktest.c 
ipchecktest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la


