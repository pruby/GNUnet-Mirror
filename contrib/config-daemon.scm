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
;;
;;
;; TODO:
;; - complete conversion of *.in to *.scm


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

;; General menu

(define (general-path builder)
 (builder
  "GNUNETD"
  "GNUNETD_HOME"
  (_ "Full pathname of GNUnet HOME directory")
  (_ 
"This gives the root-directory of the GNUnet installation. Make sure there is some space left in that directory. :-)  Users inserting or indexing files will be able to store data in this directory up to the (global) quota specified below.  Having a few gigabytes of free space is recommended." ) 
  '()
  #t
  "/var/lib/GNUnet"
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

(define (general-loglevel builder)
 (builder
  "GNUNETD"
  "LOGLEVEL"
  (_ "Log level")
  (_ "How verbose should the logging of errors be?")
  '()
  #t
  "WARNING"
  (list "NOTHING" "DEBUG" "STATUS" "INFO" "WARNING" "ERROR" "FATAL")
  'always) )

(define (general-logfile builder)
 (builder
  "GNUNETD"
  "LOGFILE"
  (_ "Where should logs go?")
  (_ 
"In which file should gnunetd write the logs?  If you specify nothing, logs are written to stderr (and note that if gnunetd runs in the background, stderr is closed and all logs are discarded)." )
  '()
  #t
  "$GNUNETD_HOME/logs"
  '()
  'advanced) )

(define (general-keeplog builder)
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
 
(define (general-pidfile builder)
 (builder
  "GNUNETD"
  "PIDFILE"
  (_ "Where should gnunetd write the PID?")
  (_ 
"In which file should gnunetd write the process-id of the server?  If you run gnunetd as root, you may want to choose /var/run/gnunetd.pid. It's not the default since gnunetd may not have write rights at that location." )
  '()
  #f
  "$GNUNET_HOME/gnunetd.pid"
  '()
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
  "udp tcp http nat"
  '()
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
  '()
  'advanced) )
 




(define (general builder)
 (builder
  "GNUNETD"
  ""
  (_ "General settings")
  (_ "Settings that change the behavior of GNUnet in general")
  (list 
    (general-path builder) 
    (general-helloexpires builder) 
    (general-loglevel builder) 
    (general-logfile builder) 
    (general-keeplog builder) 
    (general-pidfile builder) 
    (general-transports builder) 
    (general-applications builder) 
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
  (list "sqstore_sqlite" "sqstore_mysql")
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
  (list "topology_default" "topology_f2f")
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
  ""
  (_ "List of friends for friend-to-friend topology")
  (_ "Specifies the name of a file which contains a list of GNUnet peer IDs that are friends.  If used with the friend-to-friend topology, this will ensure that GNUnet only connects to these peers (via any available transport).")
  '()
  #f
  "$GNUNET_HOME/friends"
  '()
  'f2f) )
 


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
  (_ "Size of the routing table.")
  (nohelp)
  '()
  #t
  65536
  (cons 1024 1048576)
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
 (_ "Set to YES if this machine is behind a NAT that limits connections from the outside to the GNUnet port. Note that if you have configured your NAT box to allow direct connections from other machines to the GNUnet ports, you should set the option to NO.  Set this only to YES if other peers cannot contact you directly.")
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

(define (tcp builder)
 (builder
 "TCP"
 ""
 (_ "TCP transport")
 (nohelp)
 (list 
   (tcp-port builder)
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

(define (udp builder)
 (builder
 "UDP"
 ""
 (_ "UDP transport")
 (nohelp)
 (list 
   (udp-port builder)
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

(define (tcp6 builder)
 (builder
 "TCP6"
 ""
 (_ "TCP6 transport")
 (nohelp)
 (list 
   (tcp6-port builder)
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

(define (udp6 builder)
 (builder
 "UDP6"
 ""
 (_ "UDP6 transport")
 (nohelp)
 (list 
   (udp6-port builder)
 )
 #t
 #f
 #f
 'udp6-loaded) )


(define (transports builder)
 (builder
  ""
  ""
  (_ "Transports")
  (nohelp)
  (list 
    (nat builder)
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


;; main-menu

(define (main builder)
 (builder 
  "Root"
  ""
  (_ "Root node")
  (nohelp)
  (list 
    (meta builder)
    (general builder) 
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
     (experimental (get-option ctx "Meta" "EXPERIMENTAL"))
     (f2f (string= (get-option ctx "MODULES" "topology") "topology_f2f") )
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
            ((eq? i 'fs-loaded)    (change-visible ctx a b fs-loaded))
            ((eq? i 'nat-unlimited)(change-visible ctx a b nat-unlimited))
            ((eq? i 'nat-loaded)   (change-visible ctx a b nat-loaded))
            ((eq? i 'udp-loaded)   (change-visible ctx a b udp-loaded))
            ((eq? i 'tcp-loaded)   (change-visible ctx a b tcp-loaded))
            ((eq? i 'udp6-loaded)  (change-visible ctx a b udp6-loaded))
            ((eq? i 'tcp6-loaded)  (change-visible ctx a b tcp6-loaded))
            (else 'nothing)
          )
   ) ) ) )
) )

