#!/bin/bash
#
# A script for very simple messaging on GNUnet AFS
#
# This script takes as its option the keyword the message is to be found 
# with and launches an editor to edit the message, before sending. The 
# recipients are supposed to monitor the previously agreed upon key.
#
#

MYNICK="rosebud"
EDITOR="vim"
INSERT="gnunet-insert"
TMPDIR="/tmp"

############################################3#########################

if [ ! $1 ] ; then
  echo "Usage: $0 KEYWORD"
  exit
fi

KEYWORD=$1
DATE=`date -u`
DATESECS=`date +%s`

TMPFILE=`mktemp $TMPDIR/gnmessage.XXXXXX`
trap "rm -f $TMPFILE" 0 2 3 4 6 7 8 10 11 12 13 15

$EDITOR $TMPFILE

if [ -s $TMPFILE ] ; then
  $INSERT -Vnx -D "from '$MYNICK' ($DATE)" -K $KEYWORD -m text/plain -f "$KEYWORD-$DATESECS.txt" $TMPFILE 
else
  echo File $TMPFILE was empty, aborting...
fi

rm -f $TMPFILE

