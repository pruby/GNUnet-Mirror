if HAVE_MYSQL
 MYSQL_DIR = sqstore_mysql dstore_mysql
endif

if HAVE_SQLITE
 SQLITE_DIR = sqstore_sqlite kvstore_sqlite dstore_sqlite
endif

if HAVE_POSTGRES
 POSTGRES_DIR = sqstore_postgres
endif

if LINUX
 VPN_DIR = vpn
endif

if HAVE_MHD
 HOSTLIST_DIR = hostlist
endif

SUBDIRS	= \
 identity \
 bootstrap_http \
 datastore \
 fragmentation \
 getoption \
 $(HOSTLIST_DIR) \
 state \
 stats \
 pingpong \
 rpc \
 session \
 $(MYSQL_DIR) \
 $(SQLITE_DIR) \
 $(POSTGRES_DIR) \
 tbench \
 template \
 topology_default \
 traffic \
 transport \
 advertising \
 dht \
 tracekit \
 $(VPN_DIR) \
 fs \
 testing \
 chat
