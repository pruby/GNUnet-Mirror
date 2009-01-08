#!/bin/sh
# make sure configure was run with coverage enabled...
lcov --directory . --zerocounters
make check
for n in `find * -name "*.gc??" | grep libs`
do
  cd `dirname $n`
  mv `basename $n` ..
  cd -
done
rm -f src/util/libgnunetutil.gcda
lcov --directory . --capture --output-file app.info
mkdir doc/coverage
genhtml -o doc/coverage app.info
