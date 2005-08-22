#!/bin/bash
#
# Looks up daily junk from gnunet. Evil twin sister of "junkinsert.sh".
#

####################################################################

POSTTIME=`date +%d.%m.%Y`

WHOLEKEY=randtest-$POSTTIME

echo Key: $WHOLEKEY

gnunet-search $WHOLEKEY


