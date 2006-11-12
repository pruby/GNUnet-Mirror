
if HAVE_MYSQL
 MYSQL_DIR = sqstore_mysql
endif

if HAVE_SQLITE
 SQLITE_DIR = sqstore_sqlite kvstore_sqlite
endif

if !MINGW
# TESTBED_DIR = testbed
if !MACOSX
 VPN_DIR = vpn
endif
endif

SUBDIRS	= \
 advertising \
 bootstrap_http \
 datastore \
 rpc \
 fragmentation \
 getoption \
 fs \
 kvstore_sqlite \
 state \
 stats \
 gap \
 identity \
 pingpong \
 session \
 $(MYSQL_DIR) \
 $(SQLITE_DIR) \
 tbench \
 template \
 topology_default \
 topology_f2f \
 tracekit \
 traffic \
 transport \
 dht \
 $(VPN_DIR)
# $(TESTBED_DIR) 
# chat
