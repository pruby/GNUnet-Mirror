find . -iname Makefile | xargs -n1 | while read i; do sed 's/test\$(EXEEXT)/test/g' "$i">tmpfile; mv tmpfile "$i"; done
make check