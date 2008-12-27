#!/bin/sh 
for n in `find * -perm +111 | grep test | grep libs`
do 
  cd `dirname $n`; 
  cd ..; 
  echo Running `basename $n`
  valgrind --tool=memcheck --leak-check=yes --suppressions=$HOME/svn/GNUnet/contrib/gnunet.supp .libs/`basename $n` 2> `basename $n`.val > `basename $n`.out || echo FAILED
  cd $HOME/svn/GNUnet/
done
