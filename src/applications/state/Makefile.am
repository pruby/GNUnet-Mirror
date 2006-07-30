INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/GNUnet

plugin_LTLIBRARIES = \
  libgnunetmodule_state.la

libgnunetmodule_state_la_SOURCES = \
  state.c
libgnunetmodule_state_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetmodule_state_la_LDFLAGS = \
  -export-dynamic -avoid-version -module



