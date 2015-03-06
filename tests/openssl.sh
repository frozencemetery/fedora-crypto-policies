#!/bin/sh

for i in profiles/*.settings;do
	. $i
	openssl ciphers $CONFIG_OPENSSL >/dev/null
	if test $? != 0;then
		exit 1
	fi
done

exit 0
