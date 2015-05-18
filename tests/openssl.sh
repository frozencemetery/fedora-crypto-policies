#!/bin/sh

TMPFILE=out-openssl.tmp
for i in profiles/*.settings;do
	. $i
	openssl ciphers $CONFIG_OPENSSL >$TMPFILE 2>&1
	if test $? != 0 && test $i != "profiles/EMPTY.settings";then
		echo "Error in $i"
		cat $TMPFILE
		exit 1
	fi
done

rm -f $TMPFILE

exit 0
