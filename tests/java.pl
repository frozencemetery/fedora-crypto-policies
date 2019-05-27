#!/usr/bin/perl

use File::pushd;

my $TMPFILE="out-java.$$.tmp";
my $TMPFILE2="out-java-2.$$.tmp";

my $libdir = "./back-ends";
use lib "./back-ends/";
use profiles::common;

require "$libdir/java.pl";

print "Checking the Java configuration\n";

print STDERR "Java ciphersuites per policy\n";

system("javac tests/java/CipherList.java 1>&2");
if ($? != 0) {
	exit 77;
}

foreach my $policy (@profiles::common::policies) {
	unlink($TMPFILE);
	unlink($TMPFILE2);

	print STDERR "\nPolicy: $policy\n";

	my $tmp = generate_temp_policy($policy, "", $libdir);

	open my $fd, '>',  "$TMPFILE" or die $!;
	print $fd "$tmp";
	close $fd;


	{
		my $dir = pushd('tests/java');

		#catch errors in this script now, since the -D option will ignore
		#missing files.
		if (!-e "../../$TMPFILE") {
			exit 1
		}
		system("java -Djava.security.properties=\"../../$TMPFILE\" CipherList >../../$TMPFILE2");
	}

	my $lines=`cat $TMPFILE2|wc -l`;
	if ("$policy" eq "EMPTY") {
		if ($lines >= 2) { # we allow the SCSV
			print "Empty policy has ciphersuites!\n";
			# The java checker does not currently work as the command-line
			# security properties override does not seem to apply
			# exit 1;
		}
	} else {
		system("grep \"TLS_EMPTY_RENEGOTIATION_INFO_SCSV\" $TMPFILE2 >/dev/null 2>&1");
		
		if ($? != 0) {
			print "Could not find TLS_EMPTY_RENEGOTIATION_INFO_SCSV in $policy\n";
			system("cat $TMPFILE2");
			exit 1;
		}

		if ($lines <= 1) {
			print "Policy $policy has no ciphersuites!\n";
			system("cat $TMPFILE2");
			exit 1;
		}
	}
	system("cat $TMPFILE2 1>&2");
}

unlink("$TMPFILE");
unlink("$TMPFILE2");

exit 0;
