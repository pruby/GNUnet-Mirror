# This script defines some basic helper functions
# that can be used with gnunet-testbed.
#
# Source the script in the testbed-shell to make
# the functions available.
#
# Author: Christian Grothoff <chrisitan@grothoff.org>

# How many peers are available in the testbed?
testbedsize() {
  ok = 0;
  PEERS=`list-peers || ok=1`;
  if test $ok == 1
  then
    return 0;
  else
    return `cat $PEERS | wc -l`
  fi
}

# Return a list of all PEER IDs.
allpeerids() {
  size=`expr testbedsize - 1`
  if test $size -ge 0
  then
    return `seq 0 $size`;
  else
    return "";
  fi
}

# Isolate the testbed from the rest of the network
# by limiting connections to other testbed peers.
isolate() {
  for n in allpeerids
  do
    connect-allow $n allpeerids
    disconnect-all $n
  done
}

# switch everything to manual topology management
manualtopology() {
  isolate;
  for n in allpeerids
  do
    helo-disable $n
  done
}

# switch everything to automatic topology management
autotopology() {
  isolate;
  for n in allpeerids
  do
    helo-enable $n
  done
}

# create a circular topology
circulartopology() {
  manualtopology;
  LAST=`testbedsize`;
  LAST=`expr $LAST - 1`
  for n in allpeerids
  do
    connect $n $LAST
    LAST=$n
  done
}

# create a clique topology
cliquetopology() {
  manualtopology;
  for n in allpeerids
  do
    for m in allpeerids 
    do
      connect $n $m
    done
  done
}

# wait until peer $1 has connectivity degree exactly $2
waitConnected() {
  EG="-1"
  while test $EG != $2
  do
    EG=`get-stat $1 "# currently connected nodes"`
    if test $EG != $2
    then  
      sleep 1
    fi
  done  
}


# upload a random file of $1 kb to peer $2 under the name $3
# Prints "OK." on success, otherwise the error message.
uploadrandomfile() {
  size=`expr $1 \* 2`
  TMPFILE=`mktemp -t randomXXXXXX` && {
    dd if=/dev/urandom of=/$TMPFILE count=$size &> /dev/null
    upload $2 $TMPFILE $3
    rm $TMPFILE
  }
}

# Delete file $2 on peer $1
deleteFile() {
  PID=`process-start -- $1 rm $2`
  last="OK.";
  while test "$last" == "OK."
  do
    sleep 1
    last=`process-signal -- $1 $PID 0`
  done
  OUT=`process-output $1 $PID`
  RET=`process-signal -- $1 $PID -1`
  if test $RET != "0"
  then
    echo "deleteFile failed: $OUT"
    return -1
  else
    return 0
  fi

}

# insert file $2 on peer $1, print GNUnet URI.
# On error, returns -1 and prints full gnunet-insert output.
# $2 may contain options, like -i for full insertion.
afsInsert() {
  PID=`process-start -- $1 gnunet-insert -u $2`
  last="OK.";
  while test "$last" == "OK."
  do
    sleep 1
    last=`process-signal -- $1 $PID 0`
  done
  OUT=`process-output $1 $PID`
  RET=`process-signal -- $1 $PID -1`
  if test $RET != "0"
  then
    echo "gnunet-insert failed: $OUT"
    return -1
  fi
  LINES=`echo $OUT | grep "gnunet://afs" | wc -l`
  if test $LINES -ne 1
  then
    echo "gnunet-insert failed: $OUT"
    return -1
  else
    echo $OUT
    return 0
  fi  
}

# download file with url $2 on peer $1 using name $3
# Prints performance on success.
afsDownload() {
  PID=`process-start -- $1 gnunet-download -V -o $3 $2`
  last="OK.";
  while test "$last" == "OK."
  do
    sleep 1
    last=`process-signal -- $1 $PID 0`
  done
  FOUT=`process-output $1 $PID`
  RET=`process-signal -- $1 $PID -1`
  OUT=`echo $FOUT | tail -n 1`
  if test "$RET" == "0"
  then
    echo $OUT
    return 0 
  else
    echo "Download failed: $FOUT"
    return -1
  fi
}


# The very basic testcase: insert, download, both on the same peer.
# Argument: $1 = ID of peer to test.
testUploadInsertDownloadLoopback() {
  PEER0=$1
  UPLOAD=`uploadrandomfile 1024 $PEER0 RANDOM1MB`
  if test "OK." != "$UPLOAD"
  then
    echo "File upload failed: $UPLOAD"
    return -1;
  else 
    URL=`afsInsert $PEER0 RANDOM1MB`
    deleteFile $PEER0 RANDOM1MB.download &> /dev/null
    afsDownload $PEER0 $URL RANDOM1MB.download  
    deleteFile $PEER0 RANDOM1MB.download &> /dev/null
  fi
}


# Test loopback functionality at a peer.
# Arguments: peer IP and port ($1 = IP, $2 = port)
testLoopback() {
  PEER0=`add-node $1 $2`
  if test 0 -le $PEER0 &> /dev/null
  then
    testUploadInsertDownloadLoopback $PEER0
  else
    echo "add-node $1 $2 failed: $PEER0";
    return -1;
  fi
}


# Quick test for the localhost peer.  No arguments.
testLocalhost() {
  testLoopback 127.0.0.1 2087
}



# Insert on one peer, download at another.
# Argument: $1 = ID of peer for insert, $2 = ID of peer for download.
testUploadInsertDownloadPeerPair() {
  PEER0=$1
  PEER1=$2
  autoconnect-disable $PEER0
  autoconnect-disable $PEER1
  disconnect-all 0
  disconnect-all 1
  waitConnected $PEER0 0
  waitConnected $PEER1 0
  connect $PEER0 $PEER1
  waitConnected $PEER0 1
  waitConnected $PEER1 1
  UPLOAD=`uploadrandomfile 1024 $PEER0 RANDOM1MB`
  if test "OK." != "$UPLOAD"
  then
    echo "File upload failed: $UPLOAD"
    return -1;
  else 
    URL=`afsInsert $PEER0 RANDOM1MB`
    deleteFile $PEER1 RANDOM1MB.download &> /dev/null
    afsDownload $PEER1 $URL RANDOM1MB.download  
    deleteFile $PEER1 RANDOM1MB.download &> /dev/null
  fi
}


