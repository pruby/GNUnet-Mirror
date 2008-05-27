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

(define (log-logfile builder)
 (builder
  "GNUNETD"
  "LOGFILE"
  (_ "Where should gnunet-clients write their logs?")
  (nohelp)
  '()
  #f
  "$GNUNET_HOME/logs"
  '()
  'rare) )

(define (logging builder)
 (builder
   "LOGGING"
   "" 
   (_ "Logging") 
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
   'advanced) )

;; general options


(define (network-host builder)
 (builder
 "NETWORK"
 "HOST"
 (_ "On which machine and port is gnunetd running (for clients)?")
 (_ "This is equivalent to the -H option.  The format is IP:PORT.")
 '()
 #t
 "localhost:2087"
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

The default is to use filenames and to break larger words at spaces (and underscores, etc.).  This should be just fine for most people. The '-' before a library name indicates that this should be executed last and makes only sense for the split-library.")
  '()
  #t
  "libextractor_filename:-libextractor_split:-libextractor_split(0123456789._ ,%@-\n_[]{};):-libextractor_lower:-libextractor_thumbnail"
  '()
  'advanced) )

(define (fs-uri-db-size builder)
 (builder
  "FS"
  "URI_DB_SIZE"
  (_ "How many entries should the URI DB table have?")
  (_ "GNUnet uses two bytes per entry on the disk.  This database is used to keep track of how a particular URI has been used in the past.  For example, GNUnet may remember that a particular URI has been found in a search previously or corresponds to a file uploaded by the user.  This information can then be used by user-interfaces to filter URI lists, such as search results.  If the database is full, older entries will be discarded.  The default value should be sufficient without causing undue disk utilization." )
  '()
  #t
  1048576
  (cons 1 1073741824)
  'rare) )

(define (gnunet-fs-autoshare-metadata builder)
 (builder
  "GNUNET-AUTO-SHARE"
  "METADATA"
  (_ "Location of the file specifying metadata for the auto-share directory")
  (nohelp)
  '()
  #t
  "$GNUNET_HOME/metadata.conf"
  '()
  'fs-loaded) )

(define (gnunet-fs-autoshare-log builder)
 (builder
  "GNUNET-AUTO-SHARE"
  "LOGFILE"
  (_ "Location of the log file for gnunet-auto-share")
  (nohelp)
  '()
  #t
  "$GNUNET_HOME/gnunet-auto-share.log"
  '()
  'fs-loaded) )

(define (fs builder)
 (builder 
  "File-Sharing"
  ""
  (_ "File-Sharing options")
  (nohelp)
  (list 
    (fs-extractors builder)
    (fs-disable-creation-time builder)
    (fs-uri-db-size builder)
    (gnunet-fs-autoshare-metadata builder)
    (gnunet-fs-autoshare-log builder)
  )
  #t 
  #f 
  #f 
  'advanced) )

(define (gnunet-gtk-plugins builder)
 (builder 
  "GNUNET-GTK"
  "PLUGINS"
  (_ "Which plugins should be loaded by gnunet-gtk?")
  (_ "Load the about plugin for the about dialog.  The daemon plugin allows starting and stopping of gnunetd and displays information about gnunetd.  The fs plugin provides the file-sharing functionality.  The stats plugin displays various statistics about gnunetd.")
  '()
  #t 
  "about daemon fs peers stats" 
  (list "MC" "about" "daemon" "fs" "peers" "stats")
  'advanced) )

(define (gnunet-gtk-stats-interval builder)
 (builder 
  "GNUNET-GTK"
  "STATS-INTERVAL"
  (_ "How frequently (in milli-seconds) should the statistics update?")
  (_ "Each pixel in the stats dialog corresponds to the time interval specified here.")
  '()
  #t 
  30000
  (cons 1 999999999)
  'stats-loaded) )


(define (gnunet-gtk-previews builder) 
 (builder
   "GNUNET-GTK"
   "DISABLE-PREVIEWS"
   (_ "Do not show thumbnail previews from meta-data in search results")
   (_ "This option is useful for people who maybe offended by some previews or use gnunet-gtk at work and would like to avoid bad surprises.")
   '()
   #t
   #f
   #f
   'fs-loaded) )

(define (gnunet-gtk-own builder) 
 (builder
   "GNUNET-GTK"
   "DISABLE-OWN"
   (_ "Do not show search results for files that were uploaded by us")
   (_ "This option is useful to eliminate files that the user already has from the search.  Naturally, enabling this option maybe confusing because some obviously expected search results would no longer show up.  This option only works if the URI_DB_SIZE option under FS is not zero (since the URI DB is used to determine which files the user is sharing)")
   '()
   #t
   #f
   #f
   'fs-loaded) )


(define (gnunet-gtk-incomingdir builder)
 (builder
  "FS"
  "INCOMINGDIR"
  (_ "To which directory should gnunet-gtk save downloads to?")
  (nohelp)
  '()
  #t
  "$HOME/gnunet-downloads"
  '()
  'fs-loaded) )

(define (gnunet-gtk builder)
 (builder 
  "gnunet-gtk"
  ""
  (_ "Options related to gnunet-gtk")
  (nohelp)
  (list 
    (gnunet-gtk-plugins builder)
    (gnunet-gtk-previews builder)
    (gnunet-gtk-own builder)
    (gnunet-gtk-incomingdir builder)
    (gnunet-gtk-stats-interval builder)
  )
  #t 
  #f 
  #f 
  'always) )

;; main-menu

(define (paths-home builder)
 (builder
  "PATHS"
  "GNUNET_HOME"
  (_ "Full pathname of GNUnet client HOME directory")
  (_ "The directory for GNUnet files that belong to the user.")
  '()
  #t
  "~/.gnunet"
  '()
  'always) )

(define (main builder)
 (builder 
  "Root"
  ""
  (_ "Root node")
  (nohelp)
  (list 
    (paths-home builder)
    (meta builder)
    (logging builder)
    (general builder)
    (fs builder)
    (gnunet-gtk builder)
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
     (stats-loaded (list? (member "stats" (string-split (get-option ctx "GNUNET-GTK" "PLUGINS") #\  ) ) ) )
     (fs-loaded (list? (member "fs" (string-split (get-option ctx "GNUNET-GTK" "PLUGINS") #\  ) ) ) )
   )
  (begin 
    (main
     (lambda (a b c d e f g h i) 
        (begin 
          (cond
            ((eq? i 'advanced)     (change-visible ctx a b advanced))
            ((eq? i 'rare)         (change-visible ctx a b rare))
            ((eq? i 'experimental) (change-visible ctx a b experimental))
            ((eq? i 'fs-loaded) (change-visible ctx a b fs-loaded))
            ((eq? i 'stats-loaded) (change-visible ctx a b stats-loaded))
            (else 'nothing)
          )
   ) ) ) )
) )

