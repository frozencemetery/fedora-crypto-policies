#!/bin/sh

for i in profiles/*.settings;do
	. $i
	TMP=`echo "$CONFIG_GNUTLS"|sed 's/SYSTEM=//g'`
	gnutls-cli --priority "$TMP" -l >/dev/null
	if test $? != 0;then
		exit 1
	fi
done

exit 0
