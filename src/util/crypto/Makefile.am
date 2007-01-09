SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = libgnunetutil_crypto.la

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS) -O3

libgnunetutil_crypto_la_LIBADD = \
 $(GCLIBADD) \
 $(top_builddir)/src/util/libgnunetutil.la 

libgnunetutil_crypto_la_LDFLAGS = $(LIBGCRYPT_LIBS) -lgmp

libgnunetutil_crypto_la_SOURCES = \
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
 hashperf \
 hashingtest \
 hostkeytest \
 kblockkey_test \
 symciphertest \
 weakkeytest

TESTS = $(check_PROGRAMS)

hashingtest_SOURCES = \
 hashingtest.c
hashingtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la  

crctest_SOURCES = \
 crctest.c
crctest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la  

kblockkey_test_SOURCES = \
 kblockkey_test.c
kblockkey_test_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la  

hostkeytest_SOURCES = \
 hostkeytest.c
hostkeytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la   

hashtest_SOURCES = \
 hashingtest.c
hashtest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la  

hashperf_SOURCES = \
 hashperf.c
hashperf_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la  

symciphertest_SOURCES = \
 symciphertest.c
symciphertest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la   

weakkeytest_SOURCES = \
 weakkeytest.c
weakkeytest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/crypto/libgnunetutil_crypto.la  

