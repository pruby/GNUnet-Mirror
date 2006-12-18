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
   "Meta-client"
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
   "Meta-client"
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
   "Meta-client"
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
   "Meta-client"
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
   (list "NOTHING" "FATAL" "ERROR" "WARNING" "INFO" "STATUS" "DEBUG")
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

(define (log-logfile builder)
 (builder
  "GNUNETD"
  "LOGFILE"
  (_ "Where should gnunetd write the logs?")
  (nohelp)
  '()
  #f
  "$HOME/.gnunet/logs"
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

;; general options


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

(define (network-host builder)
 (builder
 "NETWORK"
 "HOST"
 (_ "On which machine runs gnunetd (for clients)")
 (_ "This is equivalent to the -H option.")
 '()
 #t
 "localhost"
 '()
 'advanced) )

(define (daemon-config builder)
 (builder
 "DAEMON"
 "CONFIGFILE"
 (_ "What is the path to the configuration file for gnunetd?")
 (_ "This option is used when clients need to start gnunetd.")
 '()
 #t
 "/etc/gnunetd.conf"
 '()
 'always) )


(define (general builder)
 (builder
   ""
   "" 
   (_ "General options")
   (nohelp)
   (list 
     (daemon-config builder)
     (network-port builder)
     (network-host builder)
   )
   #t
   #f
   #f
   'always) )

;; file-sharing options

(define (fs-disable-creation-time builder) 
 (builder
   "FS"
   "DISABLE-CREATION-TIME"
   (_ "Do not add metadata listing the creation time for inserted content")
   (nohelp)
   '()
   #t
   #t
   #f
   'advanced) )

(define (fs-extractors builder)
 (builder
  "FS"
  "EXTRACTORS"
  (_ "Which non-default extractors should GNUnet use for keyword extractors")
  (_ "Specify which additional extractor libraries should be used.  gnunet-insert uses libextractor to extract keywords from files. libextractor can be dynamically extended to handle additional file formats. If you want to use more than the default set of extractors, specify additional extractor libraries here.  The format is [[-]LIBRARYNAME[:[-]LIBRARYNAME]*].

The default is to use filenames and to break larger words at spaces (and underscores, etc.).  This should be just fine for most people. The - before a library name indicates that this should be executed last and makes only sense for the split-library.")
  '()
  #t
  "libextractor_filename:-libextractor_split:-libextractor_lower:-libextractor_thumbnail"
  '()
  'advanced) )

(define (fs builder)
 (builder 
  "File-Sharing"
  ""
  (_ "File-Sharing options")
  (nohelp)
  (list 
    (fs-extractors builder)
    (fs-disable-creation-time builder)
  )
  #t 
  #f 
  #f 
  'always) )

;; main-menu

(define (general-path builder)
 (builder
  "GNUNETD"
  "GNUNETD_HOME"
  (_ "Full pathname of GNUnet client HOME directory")
  (_ "The directory for GNUnet files that belong to the user.")
  '()
  #t
  "$HOME/.gnunet"
  '()
  'always) )

(define (main builder)
 (builder 
  "Root"
  ""
  (_ "Root node")
  (nohelp)
  (list 
    (general-path builder)
    (meta builder)
    (logging builder)
    (general builder)
    (fs builder)
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
     (advanced (get-option ctx "Meta-client" "ADVANCED"))
     (rare (get-option ctx "Meta-client" "RARE"))
     (experimental (get-option ctx "Meta-client" "EXPERIMENTAL"))
   )
  (begin 
    (main
     (lambda (a b c d e f g h i) 
        (begin 
          (cond
            ((eq? i 'advanced)     (change-visible ctx a b advanced))
            ((eq? i 'rare)         (change-visible ctx a b rare))
            ((eq? i 'experimental) (change-visible ctx a b experimental))
            (else 'nothing)
          )
   ) ) ) )
) )

