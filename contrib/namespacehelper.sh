#!/bin/bash
#
# This helper script can be used to create and maintain 
# _regularly updated_ namespace entries. The configuration phase is
# a bit tedious but after that it should work pretty transparently.
#
# You must edit the following options by hand at the start of 
# this file.
# 
# TITLE:         name of this namespace entry, i.e. "thedump".
# DESCRIPTION:   description for the namespace content/topic 
# PSEUDONYM:     your pseudonym that owns the namespace 
#                (must be created with gnunet-pseudonym-create) 
# ACCESSKEY:     to find the namespace entry, i.e. as in
#                gnunet-search-sblock 23EFCC2809382AA62392...9388 ACCESSKEY
# BASEDIR:       directory that represents the content to be inserted 
# STOREDBLOCK:   path to store the sblock data file. Will be created when 
#                the script is run with "create" and is required on 
#                updates. Keep in safe location. Don't lose it.
# ADVERTISEKEYS: global space keywords to advertise the namespace on.
# INTERVALSECS:  how often the entry is to be updated. In seconds. 
#                Should not be changed later without changing ACCESSKEY too.
# FEEDBACK:      keystring of the user-feedback channel
#                (i.e. "thedump-messages").
#
# INSERT:     gnunet-insert, possibly with path if required
# SEARCH:     gnunet-search, possibly with path if required 
# LISTPSEUDO: gnunet-pseudonym-list, possibly with path if required 
#
# This script is used as follows:
#
# a) create a pseudonym w/ gnunet-pseudonym-create
# b) edit this script 
# c) put stuff into $BASEDIR
# d) create and insert the namespace entry (first time only!)
#    $ namespacehelper.sh create
# e) publish some advertisements in global keyspace (once is enough)
#    $ namespacehelper.sh advertise
# f) finally, add 
#    namespacehelper.sh update
#    to /etc/crontab with period matching $INTERVALSECS, i.e.
#    for update-each-24H, make it run daily.
#
# After performing a) to f), the namespace can be updated simply
# by making changes to BASEDIR directory contents and letting crond 
# handle the updates. Remember that if the update is not done for 
# each interval (period), the entry will be unaccessible from GNUnet
# during that time.
#
# To promote informal protocols, the script also supposes 
# that there is a globalspace key $FEEDBACK that can be used to insert 
# user feedback. If so, the users can apply "contrib/gnmessage.sh" 
# to send messages with that key. The messages can be looked up by 
# either with "./namespacehelper.sh scan" or just gnunet-search. If 
# the key becomes flooded, the namespace owner can publish a 
# new key in the namespace.
#
# Known bugs: this script breaks if pseudonym name contains a space
#
# Report bugs to <gnunet-developers@gnu.org>  
#

# Required options

TITLE="myspace"
DESCRIPTION="My namespace"
PSEUDONYM="roger"
ACCESSKEY="root"
BASEDIR="/home/roger/myspace/"
STOREDBLOCK="/home/roger/myspace.sblock"
ADVERTISEKEYS="-K namespaces -K namespaces-2004" 
INTERVALSECS=$[60*60*24]
FEEDBACK="$TITLE-messages"

# Utilities used

SEARCH="gnunet-search"
INSERT="gnunet-insert"
# if required, use 
# INSERT="gnunet-insert -p [your pseudonym password]"
LISTPSEUDO="gnunet-pseudonym-list"
# if required, use 
# LISTPSEUDO="gnunet-pseudonym-list -p [your pseudonym password]"


## [ PROBABLY NO USER-SERVICEABLE PARTS BELOW ]########################


if [ ! $1 ] ; then
  echo "Usage: $0 [help|create|advertise|update|scan]"
  exit
fi


case $1 in
        help)
		echo "MUST_READ usage instructions are at the start of this script."
		;;
	advertise)
		HASH=`$PSEUDOLIST | grep $PSEUDONYM | sed -e "s/.* //g"`
		if [ -z $HASH ] ; then
		  echo Could not find $PSEUDONYM.
		  exit
		fi

		TMPFILE=`mktemp namespacehelper.XXXXXX`
		trap "rm -f $TMPFILE" 0 2 3 4 6 7 8 10 11 12 13 15

		BLURB="$TITLE : $HASH $ACCESSKEY" 
		echo Sending advert as $BLURB on $ADVERTISEKEYS 
		echo $BLURB >$TMPFILE
		echo Feedback channel : $FEEDBACK >>$TMPFILE

		$INSERT -nVXx -m "text/plain" -f "$TITLE.txt" $ADVERTISEKEYS -D "$BLURB" "$TMPFILE"
		;;
	create)
		echo 1st time indexing dir $BASEDIR under $ACCESSKEY
		$INSERT -VbrX -s $PSEUDONYM -o "$STOREDBLOCK" -t $ACCESSKEY -i $INTERVALSECS -D "$DESCRIPTION" "$BASEDIR"
		;;
	update)
		echo Updating entry $ACCESSKEY with $BASEDIR ... 
		$INSERT -VbrX -s $PSEUDONYM -e "$STOREDBLOCK" -o "$STOREDBLOCK" "$BASEDIR"
		;;
	scan)
		echo Scanning for messages ...
		$SEARCH "$FEEDBACK"
		;;
esac


