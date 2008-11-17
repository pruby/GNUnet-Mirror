SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = libcrypto.la

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS) -O3

libcrypto_la_LIBADD = \
 $(GCLIBADD) \
 $(LIBGCRYPT_LIBS) \
 -lgmp

libcrypto_la_SOURCES = \
 crc32.c \
 hashing.c \
 hostkey_gcrypt.c \
 kblockkey.c \
 locking_gcrypt.c locking_gcrypt.h \
 random.c \
 symcipher_gcrypt.c 

check_PROGRAMS = \
 crctest \
 hashtest \
 hashperf_test \
 hashingtest \
 hostkeytest \
 kblockkey_test \
 symciphertest \
 weakkeytest

TESTS = $(check_PROGRAMS)

hashingtest_SOURCES = \
 hashingtest.c
hashingtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

crctest_SOURCES = \
 crctest.c
crctest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

kblockkey_test_SOURCES = \
 kblockkey_test.c
kblockkey_test_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

hostkeytest_SOURCES = \
 hostkeytest.c
hostkeytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

hashtest_SOURCES = \
 hashingtest.c
hashtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

hashperf_test_SOURCES = \
 hashperf.c
hashperf_test_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

symciphertest_SOURCES = \
 symciphertest.c
symciphertest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

weakkeytest_SOURCES = \
 weakkeytest.c
weakkeytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la 

