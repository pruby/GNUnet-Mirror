INCLUDES = -I$(top_srcdir)/src/include
SUBDIRS  = m4 po libltdl src doc contrib

if USE_GCRYPT
  DISTCHECK_CONFIGURE_FLAGS=--with-gcrypt
endif
if USE_OPENSSL
  DISTCHECK_CONFIGURE_FLAGS=--with-crypto
endif

EXTRA_DIST = \
 ABOUT-NLS \
 config.rpath  \
 README.fr \
 UPDATING \
 PLATFORMS \
 acinclude.m4

ACLOCAL_AMFLAGS = -I m4
