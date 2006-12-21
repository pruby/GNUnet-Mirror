INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = libwin.la

if MINGW
  libwin_la_SOURCES = \
     winproc.c \
     win.cc
endif

if CYGWIN
  libwin_la_SOURCES = \
     winproc.c
endif

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -lstdc++ -lcomdlg32 -lplibc
endif

if CYGWIN
  CYGFLAGS = -Wl,--no-undefined -Wl,--export-all-symbol
endif

libwin_la_LDFLAGS = \
  -export-dynamic $(WINFLAGS) $(CYGFLAGS) $(LIBS)

