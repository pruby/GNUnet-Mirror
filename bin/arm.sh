#!/bin/sh
# This script is the current "state of the art" of compiling GNUnet for the
# Sharp Zaurus SL5000. It does not work yet. You need to download the cross
# compiler rpms from the Sharp website to get it to "compile" -- note that
# it does not link...

# This is where the rpm installs the compiler, must be in the path!
export PATH=/opt/Embedix/tools/bin/:$PATH

# you may want to edit "configure" to force "linux" for host_os to be accepted
# for generating shared libraries (the generated configure expects "linux-gnu" which
# for some reason is not what it detects for the cross compilation. 
#
# If you do that, the build fails when executables are linked with "malloc_rpl" not
# found/resolved. Beats me.
./configure --host=arm-linux  --with-crypto=/opt/Embedix/ --with-storage=directory --without-gtk
