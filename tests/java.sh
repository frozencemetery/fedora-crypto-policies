#!/bin/sh

TMPFILE=java.$$.tmp
TMPFILE2=java-out.$$.tmp

echo "Java ciphersuites per policy"

javac tests/java/CipherList.java
if test $? != 0;then
	exit 77
fi

for i in profiles/*;do
	rm -f $TMPFILE $TMPFILE2

	policy=$(basename $i)

	if grep -q '@' <<<$policy; then
		continue
	fi

	echo ""
	echo "Policy: $policy"
	. $i
	echo "$CONFIG_JAVA" >$TMPFILE
	pushd tests/java >/dev/null
	#catch errors in this script now, since the -D option will ignore
	#missing files.
	test -f "../../$TMPFILE" || exit 1
	java -Djava.security.properties="../../$TMPFILE" CipherList >../../$TMPFILE2
	popd >/dev/null

	lines=$(cat $TMPFILE2|wc -l)
	if test "$policy" = "EMPTY";then
		if test $lines -ge 2;then # we allow the SCSV
			echo "Empty policy has ciphersuites!"
			echo "Policy: $CONFIG_JAVA"
			cat $TMPFILE2
			exit 1
		fi
	else
		grep "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" $TMPFILE2 >/dev/null 2>&1
		
		if test $? != 0;then
			echo "Could not find TLS_EMPTY_RENEGOTIATION_INFO_SCSV in $policy"
			cat $TMPFILE2
			exit 1
		fi

		if test $lines -le 1;then
			echo "Policy $policy has no ciphersuites!"
			cat $TMPFILE2
			exit 1
		fi
	fi
	cat $TMPFILE2
done

rm -f $TMPFILE $TMPFILE2

exit 0
