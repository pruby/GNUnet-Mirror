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

while true; do
 echo -n HTTP/1.0 200 OK > /tmp/gnunet-hostlist-$$
 echo -e "\r\n\r" >> /tmp/gnunet-hostlist-$$
 cat $GNUNETD_HOME/data/hosts/$NODE.* >> /tmp/gnunet-hostlist-$$
 nc -q 1 -l -p $PORT < /tmp/gnunet-hostlist-$$ > /dev/null
 if test $? -ne 0; then
  rm /tmp/gnunet-hostlist*
  exit;
 fi
 rm /tmp/gnunet-hostlist-$$
done;
