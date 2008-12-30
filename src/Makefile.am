if WANT_FRAMEWORK
  INTLEMU_SUBDIRS = intlemu
endif

SUBDIRS = include $(INTLEMU_SUBDIRS) util libs setup server transports applications

if WANT_FRAMEWORK
lib_LTLIBRARIES = libgnunet.la
endif

libgnunet_la_SOURCES =
libgnunet_la_LIBADD = \
 util/libgnunetutil.la \
 setup/lib/libgnunetsetup.la \
 applications/fs/libgnunetecrs_core.la \
 applications/fs/lib/libgnunetfs.la \
 applications/rpc/libgnunetrpc_util.la \
 applications/identity/libgnunetidentity_api.la \
 applications/getoption/libgnunetgetoption_api.la \
 applications/dht/tools/libgnunetdht_api.la \
 applications/stats/libgnunetstats_api.la \
 applications/tracekit/libgnunettracekit_api.la \
 applications/traffic/libgnunettraffic_api.la \
 applications/chat/lib/libgnunetchat_api.la \
 applications/testing/libgnunetremote_api.la \
 applications/testing/libgnunettesting_api.la \
 applications/fs/ecrs/libgnunetecrs.la \
 applications/fs/uritrack/libgnuneturitrack.la \
 applications/fs/namespace/libgnunetnamespace.la \
 applications/fs/fsui/libgnunetfsui.la \
 applications/fs/collection/libgnunetcollection.la
 
