#!/usr/bin/perl

my $TMPFILE="out-openssl.tmp";

my $libdir = "./back-ends";
use lib "./back-ends/";
use profiles::common;

print "Checking the OpenSSL configuration\n";

require "$libdir/openssl.pl";

foreach my $policy (@profiles::common::policies) {

	my $tmp = generate_temp_policy($policy, "", $libdir);

	system("openssl ciphers $tmp >$TMPFILE 2>&1") if $policy ne 'EMPTY';
	if ($? != 0) {
		print "Error in OpenSSL policy for $policy\n";
		system("cat $TMPFILE 1>&2");
		print STDERR "ciphers: $tmp\n";
		exit 1;
	}
	unlink($TMPFILE);
}

exit 0;
