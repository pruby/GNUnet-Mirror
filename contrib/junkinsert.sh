#!/bin/sh
#
# This evil script inserts junk data to flood gnunet. Seriously,
# it creates random content that can be fetched by other people
# to test the network. The idea is to provide fresh test content 
# each day and yet so that it can be found easily with a key
# that is relatively unique yet deterministic:
#
# Key: randtest-DAY.MONTH.YEAR
#
# It is left to the gnunet itself to a) make sure approach
# like this can't be used to harm the network b) the inserted
# random blocks disappear from the data caches in reasonable time.
#
# You can run this script daily from e.g. crond. Note that this only
# pollutes your own nodecache if no-one requests the inserted data.
#
# Replace "jerry" below with your personal nickname.
#

SENDER="jerry"
SIZEINKBS=64
PRIORITY=32

####################################################################

TMPFILE=`mktemp /tmp/gn_insertjunk.XXXXXX` || exit 1
rm $TMPFILE
dd count=$SIZEINKBS bs=1024 if=/dev/urandom of=$TMPFILE >/dev/null 2>&1
POSTTIME=`date +%d.%m.%Y`
WHOLEKEY=randtest-$POSTTIME
echo Key: $WHOLEKEY
gnunet-insert -p $PRIORITY -n -x -k $WHOLEKEY -f $WHOLEKEY -D "Random test by $SENDER" $TMPFILE
rm $TMPFILE


