INCLUDES = -I$(top_srcdir)/src/include

SUBDIRS = .

EXTRA_DIST = timertimer.c

noinst_LTLIBRARIES = \
  libthreads.la

libthreads_la_SOURCES = \
 mutex.c \
 pthread.c \
 semaphore.c \
 shutdown.c \
 signal.c \
 time.c

check_PROGRAMS = \
 semaphoretest \
 shutdowntest \
 shutdowntest2 \
 timertest 

TESTS = $(check_PROGRAMS)

semaphoretest_SOURCES = \
 semaphoretest.c
semaphoretest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

shutdowntest_SOURCES = \
 shutdowntest.c
shutdowntest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

shutdowntest2_SOURCES = \
 shutdowntest2.c
shutdowntest2_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

timertest_SOURCES = \
 timertest.c
timertest_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
