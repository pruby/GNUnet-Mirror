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
;; First, a function "setup" which constructs the
;; configuration tree.
;;
;; Second, a function "change" which is notified whenever
;; configuration options are changed; the script can then
;; change the visibility of other options.
;;

(define (change ctx root changed)
 ( 0 ) )

(define (setup)
 (build-tree-node "" "" "" "" () #t #f #f) )

