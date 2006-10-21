INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

lib_LTLIBRARIES = \
  libgnunetutil_boot.la

libgnunetutil_boot_la_SOURCES = \
  startup.c

libgnunetutil_boot_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/util/config_impl/libgnunetutil_config.la \
 $(top_builddir)/src/util/loggers/libgnunetutil_logging.la 

