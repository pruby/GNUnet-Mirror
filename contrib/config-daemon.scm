;; This is not a stand-alone guile application.
;; It can only be executed from within gnunet-setup.
;;
;; GNUnet setup defines a function "build-tree-node"
;; (with arguments section, option, description, help,
;;  children, visible, value and range) which is
;;  used by the script to create the configuration tree.
;;
;; GNUnet setup defines a function "change-visible"
;; (with arguments context, section, option, yesno) which
;;  can be used by the script to dynamically change the
;;  visibility of options.
;;
;; GNUnet setup defines a function "get-option"
;; (with arguments context, section, option) which
;;  can be used to query the current value of an option.
;;
;; GNUnet setup defines a function "set-option"
;; (with arguments context, section, option, value) which
;;  can be used to set the value of an option.
;;
;;
;; GNUnet setup requires two functions from this script.
;; First, a function "gnunet-config-setup" which constructs the
;; configuration tree.
;;
;; Second, a function "gnunet-config-change" which is notified whenever
;; configuration options are changed; the script can then
;; change the visibility of other options.


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; for GNU gettext
(define (_ msg) (gettext msg "GNUnet"))

;; common string
(define (nohelp) 
  (_ "No help available.") )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; menu definitions

;; meta-menu

(define (meta-exp builder) 
 (builder
   "Meta"
   "EXPERIMENTAL"
   (_ "Prompt for development and/or incomplete code")
   (_
"If EXPERIMENTAL is set to NO, options for experimental code are not shown.  If in doubt, use NO.

Some options apply to experimental code that maybe in a state of development where the functionality, stability, or the level of testing is not yet high enough for general use.  These features are said to be of \"alpha\" quality.  If a feature is currently in alpha, uninformed use is discouraged (since the developers then do not fancy \"Why doesn't this work?\" type messages).

However, active testing and qualified feedback of these features is always welcome.  Users should just be aware that alpha features may not meet the normal level of reliability or it may fail to work in some special cases.  Bug reports are usually welcomed by the developers, but please read the documents <file://README> and <http://gnunet.org/faq.php3> and use <https://gnunet.org/mantis/> for how to report problems." )
   '()
   #t
   #f
   #f
   'advanced) )

(define (meta-adv builder) 
 (builder
   "Meta"
   "ADVANCED"
   (_ "Show options for advanced users")
   (_
"These are options that maybe difficult to understand for the beginner. These options typically refer to features that allow tweaking of the installation.  If in a hurry, say NO." )
   '()
   #t
   #t
   #f
   'always) )

(define (meta-rare builder) 
 (builder
  "Meta"
   "RARE"
   (_ "Show rarely used options")
   (_
"These are options that hardly anyone actually needs.  If you plan on doing development on GNUnet, you may want to look into these.  If in doubt or in a hurry, say NO." )
   '()
   #t
   #t
   #f
   'advanced) )

(define (meta builder)
 (builder
   "Meta"
   "" 
   (_ "Meta-configuration") 
   (_ "Which level of configuration should be available")
   (list 
     (meta-adv builder) 
     (meta-rare builder)
     (meta-exp builder)
   )
   #t
   #f
   #f
   'always) )

;; paths

(define (paths-home builder)
 (builder
  "PATHS"
  "GNUNETD_HOME"
  (_ "Full pathname of GNUnet HOME directory")
  (_ 
"This gives the root-directory of the GNUnet installation. Make sure there is some space left in that directory. :-)  Users inserting or indexing files will be able to store data in this directory up to the (global) quota specified below.  Having a few gigabytes of free space is recommended." ) 
  '()
  #t
  "/var/lib/gnunet"
  '()
  'always) )

;; General menu

(define (fs-path builder)
 (builder
  "FS"
  "DIR"
  (_ "Full pathname of GNUnet directory for file-sharing data")
  (nohelp) 
  '()
  #t
  "$GNUNETD_HOME/data/fs"
  '()
  'always) )

(define (kv-path builder)
 (builder
  "KEYVALUE_DATABASE"
  "DIR"
  (_ "Full pathname to the directory with the key-value database")
  (_ "Note that the kvstore is currently not used.") 
  '()
  #f
  "$GNUNET_HOME/kvstore/"
  '()
  'never) )

(define (index-path builder)
 (builder
  "FS"
  "INDEX-DIRECTORY"
  (_ "Full pathname of GNUnet directory for indexed files symbolic links")
  (nohelp) 
  '()
  #t
  "$GNUNETD_HOME/data/shared"
  '()
  'always) )

(define (general-helloexpires builder)
 (builder
  "GNUNETD"
  "HELLOEXPIRES"
  (_ "How many minutes should peer advertisements last?")
  (_ 
"How many minutes is the current IP valid?  (GNUnet will sign HELLO messages with this expiration timeline. If you are on dialup, 60 (for 1 hour) is suggested. If you are having a static IP address, you may want to set this to a large value (say 14400).  The default is 1440 (1 day). If your IP changes periodically, you will want to choose the expiration to be smaller than the frequency with which your IP changes." )
  '()
  #t
  1440
  (cons 1 14400)
  'advanced) )

(define (general-hostlisturl builder)
 (builder
  "GNUNETD"
  "HOSTLISTURL"
  (_ "Where can GNUnet find an initial list of peers?")
  (_ 
"GNUnet can automatically update the hostlist from the web. While GNUnet internally communicates which hosts are online, it is typically a good idea to get a fresh hostlist whenever gnunetd starts from the WEB. By setting this option, you can specify from which server gnunetd should try to download the hostlist. The default should be fine for now.
		
The general format is a list of space-separated URLs.  Each URL must have the format http://HOSTNAME/FILENAME
		
If you want to setup an alternate hostlist server, you must run a permanent node and \"cat data/hosts/* > hostlist\" every few minutes to keep the list up-to-date.
		
If you do not specify a HOSTLISTURL, you must copy valid hostkeys to data/hosts manually.")
  '()
  #t
  "http://gnunet.org/hostlist.php http://gnunet.mine.nu:8081/hostlist http://de.gnunet.org/cgi-bin/hostlist.cgi"
  '()
  'always) )

(define (general-http-proxy builder)
 (builder
  "GNUNETD"
  "HTTP-PROXY"
  (_ "HTTP Proxy Server")
  (_ 
"If you have to use a proxy for outbound HTTP connections, specify the proxy configuration here.  Default is no proxy." )
  '()
  #t
  ""
  '()
  'advanced) )


;; logging options

(define (log-level description option builder)
 (builder
   "LOGGING"
   option
   description
   (nohelp)
   '()
   #t
   "WARNING"
   (list "SC" "NOTHING" "FATAL" "ERROR" "WARNING" "INFO" "STATUS" "DEBUG")
   'always))

;; option not supported / used at the moment (useful?)
;(define (log-conf-date builder)
; (builder
;   "LOGGING"
;   "DATE"
;   (_ "Log the date of the event")
;   (nohelp)
;   '()
;   #t
;   #t
;   #t
;   'advanced))

(define (log-keeplog builder)
 (builder
  "GNUNETD"
  "KEEPLOG"
  (_ "How long should logs be kept?")
  (_ 
"How long should logs be kept? If you specify a value greater than zero, a log is created each day with the date appended to its filename. These logs are deleted after $KEEPLOG days.	To keep logs forever, set this value to 0." )
  '()
  #t
  3
  (cons 0 36500)
  'advanced) )

(define (daemon-fdlimit builder)
 (builder
  "GNUNETD"
  "FDLIMIT"
  (_ "What maximum number of open file descriptors should be requested from the OS?")
  (_ 
"The default of 1024 should be fine for most systems.  If your system can support more, increasing the number might help support additional clients on machines with plenty of bandwidth.  For embedded systems, a smaller number might be acceptable.  A value of 0 will leave the descriptor limit untouched.  This option is mostly for OS X systems where the default is too low.  Note that if gnunetd cannot obtain the desired number of file descriptors from the operating system, it will print a warning and try to run with what it is given." )
  '()
  #t
  1024
  (cons 64 65536)
  'rare) )

(define (log-logfile builder)
 (builder
  "GNUNETD"
  "LOGFILE"
  (_ "Where should gnunetd write the logs?")
  (nohelp)
  '()
  #f
  "$GNUNET_HOME/daemon-logs"
  '()
  'rare) )

(define (logging builder)
 (builder
   "LOGGING"
   "" 
   (_ "Configuration of the logging system") 
   (_ "Specify which system messages should be logged how")
   (list 
     (log-keeplog builder)
     (log-logfile builder)
     (log-level (_ "Logging of events for users") "USER-LEVEL" builder) 
     (log-level (_ "Logging of events for the system administrator") "ADMIN-LEVEL" builder) 
   )
   #t
   #f
   #f
   'always) )

 
(define (general-pidfile builder)
 (builder
  "GNUNETD"
  "PIDFILE"
  (_ "Where should gnunetd write the PID?")
  (_ "The default is no longer /var/run/gnunetd.pid since we could not delete the file on shutdown at that location." )
  '()
  #f
  "/var/run/gnunetd/pid"
  '()
  'rare) )


(define (general-username builder)
 (builder
  "GNUNETD"
  "USER"
  (_ "As which user should gnunetd run?")
  (_ 
"Empty means \"current user\". On computer startup, it is root/SYSTEM.  Under Windows, this setting affects the creation of a new system service only.")
  '()
  #f
  ""
  '()
  'advanced) )
 


(define (general-autostart builder)
 (builder
 "GNUNETD"
 "AUTOSTART"
 (_ "Should gnunetd be automatically started when the system boots?")
 (_ "Set to YES if gnunetd should be automatically started on boot.  If this option is set, gnunet-setup will install a script to start the daemon upon completion.  This option may not work on all systems.")
 '()
 #t
 #f
 #f
 'rare) )


(define (general-transports builder)
 (builder
  "GNUNETD"
  "TRANSPORTS"
  (_ "Which transport mechanisms should GNUnet use?")
  (_ 
"Use space-separated list of the modules, e.g.  \"udp smtp tcp\".  The available transports are udp, tcp, http, smtp, tcp6, udp6 and nat.
		
Loading the 'nat' and 'tcp' modules is required for peers behind NAT boxes that cannot directly be reached from the outside.  Peers that are NOT behind a NAT box and that want to *allow* peers that ARE behind a NAT box to connect must ALSO load the 'nat' module.  Note that the actual transfer will always be via tcp initiated by the peer behind the NAT box.  The nat transport requires the use of tcp, http, smtp and/or tcp6 in addition to nat itself.")
  '()
  #t
  "udp tcp nat"
  (list "MC" "udp" "udp6" "tcp" "tcp6" "nat")
  'advanced) )
 

(define (general-applications builder)
 (builder
  "GNUNETD"
  "APPLICATIONS"
  (_ "Which applications should gnunetd support?")
  (_ 
"Whenever this option is changed, you MUST run gnunet-update. Currently, the available applications are:

advertising: advertises your peer to other peers. Without it, your peer will not participate in informing peers about other peers.  You should always load this module.

getoption:  allows clients to query gnunetd about the values of various configuration options.  Many tools need this.  You should always load this module.

stats: allows tools like gnunet-stats and gnunet-gtk to query gnunetd about various statistics.  This information is usually quite useful to diagnose errors, hence it is recommended that you load this module.

traffic: keeps track of how many messages were recently received and transmitted.  This information can then be used to establish how much cover traffic is currently available.  The amount of cover traffic becomes important if you want to make anonymous requests with an anonymity level that is greater than one.  It is recommended that you load this module.

fs: needed for anonymous file sharing. You should always load this module.

chat: broadcast chat (demo-application, ALPHA quality).	Required for gnunet-chat.  Note that the current implementation of chat is not considered to be secure.

tbench: benchmark transport performance.  Required for gnunet-tbench.  Note that tbench allows other users to abuse your resources.

tracekit: topology visualization toolkit.  Required for gnunet-tracekit. Note that loading tracekit will make it slightly easier for an adversary to compromise your anonymity." )
  '()
  #t
  "advertising getoption fs stats traffic"
  (list "MC" "advertising" "getoption" "fs" "stats" "traffic" "dht" "tracekit" "tbench" "vpn" "chat")
  'advanced) )
 


(define (tcpserver-disable builder)
 (builder
 "TCPSERVER"
 "DISABLE"
 (_ "Disable client-server connections")
 (nohelp)
 '()
 #t
 #f
 #f
 'advanced) )

(define (gnunetd-private-network builder)
 (builder
 "GNUNETD"
 "PRIVATE-NETWORK"
 (_ "Disable peer discovery")
 (_ "The option 'PRIVATE-NETWORK' can be used to limit the connections of this peer to peers of which the hostkey has been copied by hand to data/hosts;  if this option is given, GNUnet will not accept advertisements of peers that the local node does not already know about.  Note that in order for this option to work, HOSTLISTURL should either not be set at all or be set to a trusted peer that only advertises the private network. Also, the option does NOT work at the moment if the NAT transport is loaded; for that, a couple of lines above would need some minor editing :-).")
 '()
 #t
 #f
 #f
 'rare) )

(define (network-disable-advertisting builder)
 (builder
 "NETWORK"
 "DISABLE-ADVERTISEMENTS"
 (_ "Disable advertising this peer to other peers")
 (nohelp)
 '()
 #t
 #f
 #f
 'rare) )

(define (network-disable-autoconnect builder)
 (builder
 "NETWORK"
 "DISABLE-AUTOCONNECT"
 (_ "Disable automatic establishment of connections")
 (_ "If this option is enabled, GNUnet will not automatically establish connections to other peers, but instead wait for applications to specifically request connections to other peers (or for other peers to connect to us).")
 '()
 #t
 #f
 #f
 'rare) )

(define (network-disable-helloexchange builder)
 (builder
 "NETWORK"
 "HELLOEXCHANGE"
 (_ "Disable advertising of other peers by this peer")
 (_ "This option maybe useful during testing, but turning it off is dangerous! If in any doubt, set it to YES (which is the default).")
 '()
 #t
 #f
 #f
 'rare) )

(define (network-port builder)
 (builder
 "NETWORK"
 "PORT"
 (_ "Client/Server Port")
 (_ "Which is the client-server port that is used between gnunetd and the clients (TCP only).  You may firewall this port for non-local machines (but you do not have to since GNUnet will perform access control and only allow connections from machines that are listed under TRUSTED).")
 '()
 #t
 2087
 (cons 1 65535)
 'advanced) )

(define (network-trusted builder)
 (builder
 "NETWORK"
 "TRUSTED"
 (_ "IPs allowed to use gnunetd server")
 (_ "This option specifies which hosts are trusted enough to connect as clients (to the TCP port).  This is useful if you run gnunetd on one host of your network and want to allow all other hosts to use this node as their server.  By default, this is set to 'loopback only'.  The format is IP/NETMASK where the IP is specified in dotted-decimal and the netmask either in CIDR notation (/16) or in dotted decimal (255.255.0.0). Several entries must be separated by a semicolon, spaces are not allowed.")
 '()
 #t
 "127.0.0.0/8;"
 '()
 'advanced) )


(define (limit-allow builder)
 (builder
 "GNUNETD"
 "LIMIT-ALLOW"
 (_ "Limit connections to the specfied set of peers.")
 (_ "If this option is not set, any peer is allowed to connect.  If it is set, only the specified peers are allowed.")
 '()
 #t
 ""
 '()
 'rare))

(define (username builder)
 (builder
 "GNUNETD"
 "USER"
 (_ "Run gnunetd as this user.")
 (_ "When started as root, gnunetd will change permissions to the given user.")
 '()
 #t
 "gnunetd"
 '()
 'advanced))

(define (groupname builder)
 (builder
 "GNUNETD"
 "GROUP"
 (_ "Run gnunetd as this group.")
 (_ "When started as root, gnunetd will change permissions to the given group.")
 '()
 #t
 "gnunetd"
 '()
 'advanced))

(define (autostart builder)
 (builder
 "GNUNETD"
 "AUTOSTART"
 (_ "Run gnunetd during system startup?")
 (nohelp)
 '()
 #t
 #t
 '()
 'rare))


(define (limit-deny builder)
 (builder
 "GNUNETD"
 "LIMIT-DENY"
 (_ "Prevent the specfied set of peers from connecting.")
 (_ "If this option is not set, any peer is allowed to connect.")
 '()
 #t
 ""
 '()
 'rare))

(define (general-advertising builder)
 (builder
  "ADVERTISING"
  ""
 (_ "Rarely used settings for peer advertisements and connections")
 (list
    (general-helloexpires builder) 
    (tcpserver-disable builder) 
    (gnunetd-private-network builder) 
    (network-disable-advertising builder) 
    (network-disable-helloexchange builder) 
    (network-disable-autoconnect builder) 
    (limit-allow builder) 
    (limit-deny builder) 
 )
  #t
  #f
  #f
  'rare) )

(define (general builder)
 (builder
  "GNUNETD"
  ""
  (_ "General settings")
  (_ "Settings that change the behavior of GNUnet in general")
  (list 
    (username builder) 
    (groupname builder) 
    (autostart builder) 
    (daemon-fdlimit builder) 
    (fs-path builder) 
    (index-path builder) 
    (general-pidfile builder) 
    (general-hostlisturl builder)
    (general-http-proxy builder)
    (network-port builder) 
    (network-trusted builder) 
    (general-username builder) 
    (general-autostart builder) 
    (general-transports builder) 
    (general-applications builder) 
  )
  #t
  #f
  #f
  'always) )


(define (paths builder)
 (builder
  "PATHS"
  ""
  (_ "Path settings")
  (_ "Prefixes for paths used by GNUnet")
  (list 
    (paths-home builder) 
  )
  #t
  #f
  #f
  'always) )


;; modules menu

(define (modules-sqstore builder)
 (builder
  "MODULES"
  "sqstore"
  (_ "Which database should be used?")
  (_ 
"Which database should be used?  The options are \"sqstore_sqlite\" and \"sqstore_mysql\".  You must run gnunet-update after changing this value!
			
In order to use sqstore_mysql, you must configure the mysql database, which is relatively simple.  Read the file doc/README.mysql for how to setup mysql." )
  '()
  #t
  "sqstore_sqlite"
  (list "SC" "sqstore_sqlite" "sqstore_mysql")
  'advanced) )

(define (modules-topology builder)
 (builder
  "MODULES"
  "topology"
  (_ "Which topology should be used?")
  (_ 
"Which topology should be used?  The only options at the moment are \"topology_default\" and \"topology_f2f\".  In default mode, GNUnet will try to connect to a diverse set of peers, and welcome connections from anyone.  In f2f (friend-to-friend) mode, GNUnet will only allow connections from peers that are explicitly listed in a FRIENDS file.  Note that you can list peers in the FRIENDS file that run in default mode.

Use f2f only if you have (trustworthy) friends that use GNUnet and are afraid of establishing (direct) connections to unknown peers." )
  '()
  #t
  "topology_default"
  (list "SC" "topology_default" "topology_f2f")
  'advanced) )



(define (modules builder)
 (builder
  "MODULES"
  ""
  (_ "Modules")
  (_ "Settings that select specific implementations for GNUnet modules")
  (list 
    (modules-sqstore builder) 
    (modules-topology builder) 
  )
  #t
  #f
  #f
  'advanced) )


;; f2f menu

(define (f2f builder)
 (builder
  "F2F"
  "FRIENDS"
  (_ "List of friends for friend-to-friend topology")
  (_ "Specifies the name of a file which contains a list of GNUnet peer IDs that are friends.  If used with the friend-to-friend topology, this will ensure that GNUnet only connects to these peers (via any available transport).")
  '()
  #f
  "$GNUNET_HOME/friends"
  '()
  'f2f) )


;; mysql menu

(define (mysql-database builder)
 (builder
  "MYSQL"
  "DATABASE"
  (_ "Name of the MySQL database GNUnet should use")
  (nohelp) 
  '()
  #t
  "gnunet"
  '()
  'mysql) )

(define (mysql-config builder)
 (builder
  "MYSQL"
  "CONFIG"
  (_ "Configuration file that specifies the MySQL username and password")
  (nohelp) 
  '()
  #t
  "/etc/my.cnf"
  '()
  'mysql) )

(define (mysql builder)
 (builder
  "MYSQL"
  ""
  (_ "Configuration of the MySQL database")
  (nohelp)
  (list
    (mysql-config builder)
    (mysql-database builder)
  )
  #t
  #f
  #f
  'mysql) )
 


;; applications menu

(define (fs-quota builder)
 (builder
  "FS"
  "QUOTA"
  (_ "MB of diskspace GNUnet can use for anonymous file sharing")
  (_
"How much disk space (MB) is GNUnet allowed to use for anonymous file sharing?  This does not take indexed files into account, only the space directly used by GNUnet is accounted for.  GNUnet will gather content from the network if the current space-consumption is below the number given here (and if content migration is allowed below).

Note that if you change the quota, you need to run gnunet-update afterwards.")
  '()
  #t
  1024
  (cons 1 1000000)
  'always))


(define (fs-gap-tablesize builder)
 (builder
  "GAP"
  "TABLESIZE"
  (_ "Size of the routing table for anonymous routing.")
  (nohelp)
  '()
  #t
  65536
  (cons 1024 1048576)
  'rare))

(define (fs-dht-tablesize builder)
 (builder
  "DHT"
  "TABLESIZE"
  (_ "Size of the routing table for DHT routing.")
  (nohelp)
  '()
  #t
  1024
  (cons 128 1048576)
  'rare))


(define (fs-activemigration builder)
 (builder
  "FS"
  "ACTIVEMIGRATION"
  (_ "Allow migrating content to this peer.")
  (_ 
"If you say yes here, GNUnet will migrate content to your server, and you will not be able to control what data is stored on your machine. 
			
If you activate it, you can claim for *all* the non-indexed (-n to gnunet-insert) content that you did not know what it was even if an adversary takes control of your machine.  If you do not activate it, it is obvious that you have knowledge of all the content that is hosted on your machine and thus can be considered liable for it.")
  '()
  #t
  #f
  #f
  'advanced))


(define (dstore-quota builder)
 (builder
  "DSTORE"
  "QUOTA"
  (_ "MB of diskspace GNUnet can use for caching DHT index data (the data will be stored in /tmp)")
  (_ "DHT index data is inherently small and expires comparatively quickly.  It is deleted whenever gnunetd is shut down.

The size of the DSTORE QUOTA is specified in MB.")
  '()
  #t
  1
  (cons 1 1024)
  'rare))
 

(define (fs builder)
 (builder
  "FS"
  ""
  (_ "Options for anonymous file sharing")
  (nohelp)
  (list
    (fs-quota builder)
    (fs-activemigration builder)
    (fs-gap-tablesize builder)
    (fs-dht-tablesize builder)
    (mysql builder)
    (dstore-quota builder)
  )
  #t
  #t
  #f
  'fs-loaded))

(define (applications builder)
 (builder
  ""
  ""
  (_ "Applications")
  (nohelp)
  (list 
    (fs builder)
  )
  #t
  #f
  #f
  'always) )

;; transport menus

(define (nat builder)
 (builder
 "NAT"
 "LIMITED"
 (_ "Is this machine unreachable behind a NAT?")
 (_ "Set to YES if this machine is behind a NAT that limits connections from the outside to the GNUnet port and that cannot be traversed using UPnP.  Note that if you have configured your NAT box to allow direct connections from other machines to the GNUnet ports or if GNUnet can open ports using UPnP, you should set the option to NO.  Set this only to YES if other peers cannot contact you directly.  You can use 'make check' in src/transports/upnp/ to find out if your NAT supports UPnP.  You can also use gnunet-transport-check with the '-p' option in order to determine which setting results in more connections.  Use YES only if you get no connections otherwise.")
 '()
 #t
 #f
 #f
 'nat-loaded) )

(define (tcp-port builder)
 (builder
 "TCP"
 "PORT"
 (_ "Which port should be used by the TCP IPv4 transport?")
 (nohelp)
 '()
 #t
 2086
 (cons 0 65535)
 'nat-unlimited))

(define (tcp-upnp builder)
 (builder
 "TCP"
 "UPNP"
 (_ "Should we try to determine our external IP using UPnP?")
 (_ "You can use 'make check' in src/transports/upnp/ to find out if your NAT supports UPnP.  You should disable this option if you are sure that you are not behind a NAT.  If your NAT box does not support UPnP, having this on will not do much harm (only cost a small amount of resources).")
 '()
 #t
 #t
 #f
 'tcp-port-nz))

(define (tcp-blacklist builder)
 (builder
 "TCP"
 "BLACKLIST"
 (_ "Which IPs are not allowed to connect?")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (tcp-whitelist builder)
 (builder
 "TCP"
 "WHITELIST"
 (_ "Which IPs are allowed to connect? Leave empty to use the IP of your primary network interface.")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (tcp builder)
 (builder
 "TCP"
 ""
 (_ "TCP transport")
 (nohelp)
 (list 
   (tcp-port builder)
   (tcp-upnp builder)
   (tcp-blacklist builder)
   (tcp-whitelist builder)
 )
 #t
 #f
 #f
 'tcp-loaded) )


(define (http-port builder)
 (builder
 "HTTP"
 "PORT"
 (_ "Which port should be used by the HTTP transport?")
 (nohelp)
 '()
 #t
 1080
 (cons 0 65535)
 'nat-unlimited))

(define (http builder)
 (builder
 "HTTP"
 ""
 (_ "HTTP transport")
 (nohelp)
 (list 
   (http-port builder)
 )
 #t
 #f
 #f
 'http-loaded) )


(define (udp-port builder)
 (builder
 "UDP"
 "PORT"
 (_ "Which port should be used by the UDP IPv4 transport?")
 (nohelp)
 '()
 #t
 2086
 (cons 0 65535)
 'advanced))

(define (udp-upnp builder)
 (builder
 "UDP"
 "UPNP"
 (_ "Should we try to determine our external IP using UPnP?")
 (_ "You can use 'make check' in src/transports/upnp/ to find out if your NAT supports UPnP. You should disable this option if you are sure that you are not behind a NAT.  If your NAT box does not support UPnP, having this on will not do much harm (only cost a small amount of resources).")
 '()
 #t
 #t
 #f
 'udp-port-nz))

(define (udp-mtu builder)
 (builder
 "UDP"
 "MTU"
 (_ "What is the maximum transfer unit for UDP?")
 (nohelp)
 '()
 #t
 1472
 (cons 1200 65500)
 'rare))

(define (udp-blacklist builder)
 (builder
 "UDP"
 "BLACKLIST"
 (_ "Which IPs are not allowed to connect?")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (udp-whitelist builder)
 (builder
 "UDP"
 "WHITELIST"
 (_ "Which IPs are allowed to connect? Leave empty to allow connections from any IP.")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (udp builder)
 (builder
 "UDP"
 ""
 (_ "UDP transport")
 (nohelp)
 (list 
   (udp-port builder)
   (udp-upnp builder)
   (udp-mtu builder)
   (udp-blacklist builder)
   (udp-whitelist builder)
 )
 #t
 #f
 #f
 'udp-loaded) )


(define (tcp6-port builder)
 (builder
 "TCP6"
 "PORT"
 (_ "Which port should be used by the TCP IPv6 transport?")
 (nohelp)
 '()
 #t
 2088
 (cons 0 65535)
 'nat-unlimited))

(define (tcp6-blacklist builder)
 (builder
 "TCP6"
 "BLACKLIST"
 (_ "Which IPs are not allowed to connect?")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (tcp6-whitelist builder)
 (builder
 "TCP6"
 "WHITELIST"
 (_ "Which IPs are allowed to connect? Leave empty to allow any IP to connect.")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (tcp6 builder)
 (builder
 "TCP6"
 ""
 (_ "TCP6 transport")
 (nohelp)
 (list 
   (tcp6-port builder)
   (tcp6-blacklist builder)
   (tcp6-whitelist builder)
 )
 #t
 #f
 #f
 'tcp6-loaded) )


(define (udp6-port builder)
 (builder
 "UDP6"
 "PORT"
 (_ "Which port should be used by the UDP IPv6 transport?")
 (nohelp)
 '()
 #t
 2088
 (cons 0 65535)
 'advanced))

(define (udp6-mtu builder)
 (builder
 "UDP6"
 "MTU"
 (_ "What is the maximum transfer unit for UDP 6?")
 (nohelp)
 '()
 #t
 1452
 (cons 1200 65500)
 'rare))

(define (udp6-blacklist builder)
 (builder
 "UDP6"
 "BLACKLIST"
 (_ "Which IPs are not allowed to connect?")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (udp6-whitelist builder)
 (builder
 "UDP6"
 "WHITELIST"
 (_ "Which IPs are allowed to connect? Leave empty to allow any IP to connect.")
 (nohelp)
 '()
 #t
 ""
 '()
 'advanced))

(define (udp6 builder)
 (builder
 "UDP6"
 ""
 (_ "UDP6 transport")
 (nohelp)
 (list 
   (udp6-port builder)
   (udp6-mtu builder)
   (udp6-blacklist builder)
   (udp6-whitelist builder)
 )
 #t
 #f
 #f
 'udp6-loaded) )


(define (network-interface builder)
 (builder
 "NETWORK"
 "INTERFACE"
 (_ "Network interface")
 (nohelp)
 '()
 #t
 "eth0"
 '()
 'nat-unlimited) )

(define (network-ip builder)
 (builder
 "NETWORK"
 "IP"
 (_ "External IP address (leave empty to try auto-detection)")
 (nohelp)
 '()
 #t
 ""
 '()
 'nat-unlimited) )

(define (network-ip6 builder)
 (builder
 "NETWORK"
 "IP6"
 (_ "External IPv6 address (leave empty to try auto-detection)")
 (nohelp)
 '()
 #t
 ""
 '()
 'ip6-loaded) )

(define (transports builder)
 (builder
  ""
  ""
  (_ "Transports")
  (nohelp)
  (list 
    (nat builder)
    (network-interface builder)
    (network-ip builder)
    (tcp builder)
    (tcp6 builder)
    (udp builder)
    (udp6 builder)
    (http builder)
  )
  #t
  #f
  #f
  'always) )



(define (load-maxdown builder)
 (builder
 "LOAD"
 "MAXNETDOWNBPSTOTAL"
 (_ "What is the maximum number of bytes per second that we may receive?")
 (nohelp)
 '()
 #t
 50000
 (cons 1 999999999)
 'always))

(define (load-maxup builder)
 (builder
 "LOAD"
 "MAXNETUPBPSTOTAL"
 (_ "What is the maximum number of bytes per second that we may send?")
 (nohelp)
 '()
 #t
 50000
 (cons 1 999999999)
 'always))

(define (load-cpu builder)
 (builder
 "LOAD"
 "MAXCPULOAD"
 (_ "What is the maximum CPU load (percentage)?")
 (_ 
"Which CPU load can be tolerated.  Load here always refers to the total system load, that is it includes CPU utilization by other processes.  A value of 50 means that once your 1 minute-load average goes over 50% non-idle, GNUnet will try to reduce CPU consumption until the load goes under the threshold.  Reasonable values are typically between 50 and 100.  Multiprocessors may use values above 100." )
 '()
 #t
 100
 (cons 0 10000)
 'always))

(define (load-io builder)
 (builder
 "LOAD"
 "MAXIOLOAD"
 (_ "What is the maximum IO load (permille)?")
 (_ 
"Which IO load can be tolerated.  Load here refers to the percentage of CPU cycles wasted waiting for IO for the entire system, that is it includes disk utilization by other processes.  A value of 10 means that once the average number of cycles wasted waiting for IO is more than 10% non-idle, GNUnet will try to reduce IO until the load goes under the threshold.  Reasonable values are typically between 10 and 75." )
 '()
 #t
 50
 (cons 0 10000)
 'always))

(define (load-cpu-hard builder)
 (builder
 "LOAD"
 "HARDCPULIMIT"
 (_ "What is the maximum CPU load (hard limit)?")
 (_ "Which CPU load can be tolerated.  This is the hard limit, so once it is reached, gnunetd will start to massively drop data to reduce the load.  Use with caution.")
 '()
 #t
 0
 (cons 0 99999)
 'advanced))

(define (load-hard-up-limit builder)
 (builder
 "LOAD"
 "HARDUPLIMIT"
 (_ "What is the maximum upstream bandwidth (hard limit)?")
 (_ "The limit is given as a percentage of the MAXNETUPBPS limit.  Use 100 to have MAXNETUPBPS be the hard limit.  Use zero for no limit.")
 '()
 #t
 0
 (cons 0 999999999)
 'advanced))

(define (load-padding builder)
 (builder
 "GNUNETD-EXPERIMENTAL"
 "PADDING"
 (_ "Should we disable random padding (experimental option)?")
 (nohelp)
 '()
 #t
 #f
 #f
 'experimental))

(define (load-basiclimiting builder)
 (builder
 "LOAD"
 "BASICLIMITING"
 (_ "Use basic bandwidth limitation? (YES/NO).  If in doubt, say YES.")
 (_ 
"Basic bandwidth limitation (YES) means simply that the bandwidth limits specified apply to GNUnet and only to GNUnet.  If set to YES, you simply specify the maximum bandwidth (upstream and downstream) that GNUnet is allowed to use and GNUnet will stick to those limitations.  This is useful if your overall bandwidth is so large that the limit is mostly used to ensure that enough capacity is left for other applications.  Even if you want to dedicate your entire connection to GNUnet you should not set the limits to values higher than what you have since GNUnet uses those limits to determine for example the number of connections to establish (and it would be inefficient if that computation yields a number that is far too high).  

While basic bandwidth limitation is simple and always works, there are some situations where it is not perfect.  Suppose you are running another application which performs a larger download. During that particular time, it would be nice if GNUnet would throttle its bandwidth consumption (automatically) and resume using more bandwidth after the download is complete.  This is obviously advanced magic since GNUnet will have to monitor the behavior of other applications. Another scenario is a monthly cap on bandwidth imposed by your ISP, which you would want to ensure is obeyed.  Here, you may want GNUnet to monitor the traffic from other applications to ensure that the combined long-term traffic is within the pre-set bounds.  Note that you should probably not set the bounds tightly since GNUnet may observe that the bounds are about to be broken but would be unable to stop other applications from continuing to use bandwidth.

If either of these two scenarios applies, set BASICLIMITING to NO. Then set the bandwidth limits to the COMBINED amount of traffic that is accepable for both GNUnet and other applications.  GNUnet will then immediately throttle bandwidth consumption if the short-term average is above the limit, and it will also try to ensure that the long-term average is below the limit.  Note however that using NO can have the effect of GNUnet (almost) ceasing operations after other applications perform high-volume downloads that are beyond the defined limits.  GNUnet would reduce consumption until the long-term limits are again within bounds.

NO only works on platforms where GNUnet can monitor the amount of traffic that the local host puts out on the network.  This is only implemented for Linux and Win32.  In order for the code to work, GNUnet needs to know the specific network interface that is used for the external connection (after all, the amount of traffic on loopback or on the LAN should never be counted since it is irrelevant).")
 '()
 #t
 #t
 #f
 'advanced))

(define (load-interfaces builder)
 (builder
 "LOAD"
 "INTERFACES"
 (_ "Network interface to monitor")
 (_ "For which interfaces should we do accounting?  GNUnet will evaluate the total traffic (not only the GNUnet related traffic) and adjust its bandwidth usage accordingly. You can currently only specify a single interface. GNUnet will also use this interface to determine the IP to use. Typical values are eth0, ppp0, eth1, wlan0, etc.  'ifconfig' will tell you what you have.  Never use 'lo', that just won't work.  Under Windows, specify the index number reported by  'gnunet-win-tool -n'.")
 '()
 #t
 "eth0"
 (list "*" "eth0" "eth1" "eth2")
 'nobasiclimit))

(define (load builder)
 (builder
  ""
  ""
  (_ "Load management")
  (nohelp)
  (list 
    (load-maxdown builder)
    (load-maxup builder)
    (load-hard-up-limit builder)
    (load-cpu builder)
    (load-io builder)
    (load-cpu-hard builder)
    (load-basiclimiting builder)
    (load-interfaces builder)
    (load-padding builder)
  )
  #t
  #f
  #f
  'always) )


;; main-menu

(define (main builder)
 (builder 
  "Root"
  ""
  (_ "Root node")
  (nohelp)
  (list 
    (meta builder)
    (paths builder)
    (general builder) 
    (logging builder)
    (load builder)
    (modules builder) 
    (f2f builder) 
    (transports builder) 
    (applications builder) 
  )
  #t 
  #f 
  #f 
  'always) )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; first main method: build tree using build-tree-node
;; The lambda expression is used to throw away the last argument,
;; which we use internally and which is not used by build-tree-node!
(define (gnunet-config-setup) 
 (main 
  (lambda (a b c d e f g h i) (build-tree-node a b c d e f g h) ) ) )


;; second main method: update visibility (and values)
;; "change" uses again the tree builder but this time
;; scans the "i" tags to determine how the visibility needs to change

(define (gnunet-config-change ctx)
 (let 
   ( 
     (advanced (get-option ctx "Meta" "ADVANCED"))
     (rare (get-option ctx "Meta" "RARE"))
     (nobasiclimit (not (get-option ctx "LOAD" "BASICLIMITING")))
     (experimental (get-option ctx "Meta" "EXPERIMENTAL"))
     (f2f (string= (get-option ctx "MODULES" "topology") "topology_f2f") )
     (tcp-port-nz (eq? (get-option ctx "TCP" "PORT") 0) )
     (udp-port-nz (eq? (get-option ctx "UDP" "PORT") 0) )
     (mysql (string= (get-option ctx "MODULES" "sqstore") "sqstore_mysql") )
     (fs-loaded (list? (member "fs" (string-split (get-option ctx "GNUNETD" "APPLICATIONS") #\  ) ) ) )
     (nat-loaded (list? (member "nat" (string-split (get-option ctx "GNUNETD" "TRANSPORTS") #\  ) ) ) )
     (nat-limited (get-option ctx "NAT" "LIMITED"))
     (nat-unlimited (not (get-option ctx "NAT" "LIMITED")))
     (tcp-loaded (list? (member "tcp" (string-split (get-option ctx "GNUNETD" "TRANSPORTS") #\  ) ) ) )
     (udp-loaded (list? (member "udp" (string-split (get-option ctx "GNUNETD" "TRANSPORTS") #\  ) ) ) )
     (tcp6-loaded (list? (member "tcp6" (string-split (get-option ctx "GNUNETD" "TRANSPORTS") #\  ) ) ) )
     (udp6-loaded (list? (member "udp6" (string-split (get-option ctx "GNUNETD" "TRANSPORTS") #\  ) ) ) )
     (http-loaded (list? (member "http" (string-split (get-option ctx "GNUNETD" "TRANSPORTS") #\  ) ) ) )
   )
  (begin 
    (if (and nat-loaded nat-limited tcp-loaded)
        (set-option ctx "TCP" "PORT" "0")
        'nothing)
    (if (and nat-loaded nat-limited tcp6-loaded)
        (set-option ctx "TCP6" "PORT" "0")
        'nothing)
    (if (and nat-loaded nat-limited http-loaded)
        (set-option ctx "HTTP" "PORT" "0")
        'nothing) 
    (main
     (lambda (a b c d e f g h i) 
        (begin 
          (cond
            ((eq? i 'advanced)     (change-visible ctx a b advanced))
            ((eq? i 'rare)         (change-visible ctx a b rare))
            ((eq? i 'experimental) (change-visible ctx a b experimental))
            ((eq? i 'f2f)          (change-visible ctx a b f2f))
            ((eq? i 'mysql)        (change-visible ctx a b mysql))
            ((eq? i 'fs-loaded)    (change-visible ctx a b fs-loaded))
            ((eq? i 'nat-unlimited)(change-visible ctx a b nat-unlimited))
            ((eq? i 'tcp-port-nz)  (change-visible ctx a b tcp-port-nz))
            ((eq? i 'udp-port-nz)  (change-visible ctx a b udp-port-nz))
            ((eq? i 'nat-loaded)   (change-visible ctx a b nat-loaded))
            ((eq? i 'udp-loaded)   (change-visible ctx a b udp-loaded))
            ((eq? i 'tcp-loaded)   (change-visible ctx a b tcp-loaded))
            ((eq? i 'udp6-loaded)  (change-visible ctx a b udp6-loaded))
            ((eq? i 'tcp6-loaded)  (change-visible ctx a b tcp6-loaded))
            ((eq? i 'ip6-loaded)   (change-visible ctx a b (or (tcp6-loaded udp6-loaded))))
            ((eq? i 'http-loaded)  (change-visible ctx a b http-loaded))
            ((eq? i 'nobasiclimit) (change-visible ctx a b nobasiclimit))
            (else 'nothing)
          )
   ) ) ) 
   (change-visible ctx "NETWORK" "PORT" (and advanced (not (get-option ctx "TCPSERVER" "DISABLE"))))
   (change-visible ctx "NETWORK" "TRUSTED" (and advanced (not (get-option ctx "TCPSERVER" "DISABLE"))))
  )
) )

