if HAVE_MYSQL
 MYSQL_DIR = sqstore_mysql dstore_mysql
endif

if HAVE_SQLITE
 SQLITE_DIR = sqstore_sqlite kvstore_sqlite dstore_sqlite
endif

if !MINGW
# TESTBED_DIR = testbed
endif
if LINUX
 VPN_DIR = vpn
endif

SUBDIRS	= \
 identity \
 testing \
 bootstrap_http \
 datastore \
 rpc \
 fragmentation \
 getoption \
 fs \
 state \
 stats \
 pingpong \
 session \
 $(MYSQL_DIR) \
 $(SQLITE_DIR) \
 tbench \
 template \
 topology_default \
 traffic \
 transport \
 advertising \
 gap \
 dht \
 tracekit \
 $(VPN_DIR)
# $(TESTBED_DIR) 
# chat
