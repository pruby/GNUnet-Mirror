#!/bin/sh
for n in `find * -name "*.c"`
do
  PF=`grep "#include" $n | head -n1 | grep platform.h | wc -l`
  if test $PF = 0
  then
    echo "$n does not include platform.h first!";
  fi
done
