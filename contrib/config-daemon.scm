;; This is not a stand-alone guile application.
;; It can only be executed from within gnunet-setup.
;;
;; GNUnet setup defines a function "build-tree-node"
;; (with arguments section, option, description, help,
;;  children, visible, value and range) which is
;;  used by the script to create the configuration tree.
;;
;; GNUnet setup also defines a function "change-visible"
;; (with arguments context, option, section, yesno) which
;;  can be used by the script to dynamically change the
;;  visibility of options.
;;
;; Finally, GNUnet setup defines a function "get-option"
;; (with arguments context, option, section) which
;;  can be used to query the current value of an option.
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
;; - support for changes to one option forcing
;;   changes to other, seemingly unrelated options
;;   (should only require another callback into C)
;; - actually convert *.in to *.scm
;; - test!


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
"If EXPERIMENTAL is set to NO, options for experimental code are not
shown.  If in doubt, use NO.

Some options apply to experimental code that maybe in a state of
development where the functionality, stability, or the level of
testing is not yet high enough for general use.  These features are
said to be of \"alpha\" quality.  If a feature is currently in alpha,
uninformed use is discouraged (since the developers then do not fancy
\"Why doesn't this work?\" type messages).

However, active testing and qualified feedback of these features is
always welcome.  Users should just be aware that alpha features may
not meet the normal level of reliability or it may fail to work in
some special cases.  Bug reports are usually welcomed by the
developers, but please read the documents <file://README> and
<http://gnunet.org/faq.php3> and use <https://gnunet.org/mantis/> for
how to report problems." )
   '()
   #t
   #f
   #f
   'always) )



(define (meta-adv builder) 
 (builder
   "Meta"
   "ADVANCED"
   (_ "Show options for advanced users")
   (_
"These are options that maybe difficult to understand for the beginner.
These options typically refer to features that allow tweaking of the
installation.  If in a hurry, say NO." )
   '()
   #t
   #t
   #f
   'always) )

(define (meta builder)
 (builder
   "Meta"
   "" 
   (_ "Meta-configuration") 
   (_ "Which level of configuration should be available")
   (list 
     (meta-exp builder)
     (meta-adv builder) 
   )
   #t
   #f
   #f
   'always) )

;; General menu

(define (general-helloexpires builder)
 (builder
  "GNUNETD"
  "HELLOEXPIRES"
  (_ "How many minutes should peer advertisements last?")
  (_
"How many minutes is the current IP valid?  (GNUnet will sign HELLO
messages with this expiration timeline. If you are on dialup, 60 (for
1 hour) is suggested. If you are having a static IP address, you may
want to set this to a large value (say 14400).  The default is 1440 (1
day). If your IP changes periodically, you will want to choose the
expiration to be smaller than the frequency with which your IP
changes." )
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

(define (general builder)
 (builder
  "GNUNETD"
  ""
  (_ "General settings")
  (_ "Settings that change the behavior of GNUnet in general")
  (list 
    (general-helloexpires builder) 
    (general-loglevel builder) 
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


;; "change" is not yet implemented.  However, the idea is to again use
;; the tree builder but this time scan use the "i" tags to determine
;; how the visibility needs to change

(define (gnunet-config-change ctx)
 (let ((advanced (get-option ctx "Meta" "ADVANCED")))
   (main
     (lambda (a b c d e f g h i) 
        (begin 
          (if (eq? i 'advanced)
            (change-visible ctx a b advanced)
            'nothing ) ) ) ) ) )

;; Example: (change-visible ctx "FOO" "BAR" #t)

;; (setup)