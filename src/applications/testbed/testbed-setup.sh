#!/bin/sh
# This is a script to automatically setup a GNUnet-testbed CLIENT.
# The script is still in its infancy.  Study it first before running it!
#
# Arguments: 
# - so far only one, the first argument can (optionally) specify the URL for
#   the testbed registration
#
# Assumptions:
# - gdbm (devel) is installed properly to be automatically found by configure
# - script is run by root (for now -- we could do without but that may
#   compromise the user account; while that maybe what is desired, automatically
#   creating a dedicated account is probably better)
# - /etc/passwd holds the user list (and can be used to test if a name is already
#   used)
# - sshd is running on the default port on this machine
# - assumes we have enough memory and space to compile libextractor and GNUnet
# - assumes CVS is available



# Configuration...
TESTBED=http://www.ovmj.org/GNUnet/testbed/
GNCVSROOT=:pserver:anonymous@ovmj.org:/var/cvs/GNUnet

# Command-line processing: first argument gives testbed-URL.
if test ! -z $1
then
  TESTBED=$1
fi

echo "This will turn this machine into a testbed node."
echo "It will give SSH access to an account on the machine to"
echo "the operator of $TESTBED."
echo "You can abort now with CTRL-C or continue with RETURN."
read || exit -1

if test "$USER" != "root"
then
  echo "This script must be run by root.  Sorry."
  exit -1;
fi



# First, find an unused username of the form "testbedXXX"
TBUSER=testbed0
LC=`grep $TBUSER /etc/passwd | wc -l`
x=1
while test $LC -gt 0
do
  TBUSER="testbed$x"
  x=`expr $x + 1`
  LC=`grep $TBUSER /etc/passwd | wc -l`
done
TARGETDIR=/home/$TBUSER

# Setup user account (including ssh login for testbed operator!)
# Q: to what can we set the shell here while still allowing ssh-port forwarding?
useradd -d $TARGETDIR -c "GNUnet testbed user" $TBUSER || exit -1

cd $TARGETDIR
mkdir -p .ssh
cd .ssh
wget $TESTBED/authorized_keys || exit -1


# Download and install libextractor and GNUnet
TMPDIR=`mktemp -dt testbed.XXXXXX` || exit 1
cd $TMPDIR

# add pserver line to .cvspass
LC=`grep "anonymous@ovmj.org:2401" ~/.cvspass | wc -l`
if test $LC == 0
then
 cat "/1 :pserver:anonymous@ovmj.org:2401/var/cvs/GNUnet A" >> ~/.cvspass
fi

cvs -z9 -d $GNCVSROOT checkout Extractor
cd Extractor
. bootstrap
./configure --prefix=$TARGETDIR --with-extractor=$TARGETDIR
make install
cd ..

cvs -z9 -d $GNCVSROOT checkout GNUnet
cd GNUnet
. bootstrap
./configure --prefix=$TARGETDIR --with-extractor=$TARGETDIR
make install
mkdir -p $TARGETDIR/.gnunet/
cat contrib/gnunet.root | \
  sed -e "s/\/var\/lib\/GNUnet/~\/.gnunet/" \
      -e "s/REGISTERURL.*/REGISTERURL = \"$TESTBED\"/" \
  > $TARGETDIR/.gnunet/gnunet.root

cd /
rm -rf $TMPDIR

# finally, start gnunetd
sudo -u $TBUSER $TARGETDIR/bin/gnunetd -c $TARGETDIR/.gnunet/gnunet.root

echo "Testbed client running..."
