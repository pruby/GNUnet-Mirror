#!/bin/sh
M=`cat $1 | wc -l`
for n in `seq 1 $M`; do A=`cat $1 | head -n $n | tail -n 1 | awk '{ print $1}'`; B=`cat ~/rename-list | head -n $n | tail -n 1 | awk '{ print $2}'`; ./rename.sh $A $B; echo "Did $A $B ($n)"; done 