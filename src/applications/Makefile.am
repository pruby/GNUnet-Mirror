if HAVE_MYSQL
 MYSQL_DIR = sqstore_mysql
endif

if HAVE_SQLITE
 SQLITE_DIR = sqstore_sqlite
endif

if !MINGW
 TESTBED_DIR = testbed
endif

SUBDIRS	= \
 advertising \
 bootstrap_http \
 chat \
 datastore \
 rpc \
 dht \
 fragmentation \
 getoption \
 fs \
 gap \
 identity \
 pingpong \
 session \
 $(MYSQL_DIR) \
 $(SQLITE_DIR) \
 stats \
 tbench \
 template \
 $(TESTBED_DIR) \
 topology_default \
 tracekit \
 traffic \
 transport
