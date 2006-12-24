#!/bin/sh
#
# This script provides a way to share your hostlist with other users
# without the need to install a real webserver.
# Replace these placeholders with your actual configuration:
#	$GNUNETD_HOME	your GNUnet directory, usually "/var/lib/GNUnet"
#	$NODE		if you want to publish *your* node's HELO only,
#           		enter its identifier (just look at the "I am.." msg
#           		at startup) here, otherwise use "*" for a complete
#           		hostlist
#	$PORT		port to listen on, usually 80
#
# Requirements:
#	netcat		http://netcat.sourceforge.net/
# Usage:
#	nohup ./serve_hostlist.sh &

if test -z "$NODE"
then
 NODE="*"
fi

if test -z "$PORT"
then
 PORT=80
fi

if test -z "$GNUNETD_HOME"
then
 GNUNETD_HOME=/var/lib/GNUnet
fi

while true
do
 echo -n HTTP/1.0 200 OK > /tmp/gnunet-hostlist-$$
 echo -e "\r\n\r" >> /tmp/gnunet-hostlist-$$
 cat $GNUNETD_HOME/data/hosts/$NODE.{2,3,4,5,6,8,12,17,23,25} >> /tmp/gnunet-hostlist-$$
 nc -q 1 -l -p $PORT < /tmp/gnunet-hostlist-$$ > /dev/null
 if test $? -ne 0; then
  rm -f /tmp/gnunet-hostlist*
  exit;
 fi
 rm -f /tmp/gnunet-hostlist-$$
done
