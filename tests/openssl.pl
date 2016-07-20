#!/usr/bin/perl

my $TMPFILE="out-openssl.tmp";

my @policies = ('LEGACY', 'DEFAULT', 'FUTURE');
my $libdir = "./back-ends";
use lib "./back-ends/";

require "$libdir/openssl.pl";

foreach my $policy (@policies) {

	my $tmp = generate_temp_policy($policy, "", $libdir);

	system("openssl ciphers $tmp >$TMPFILE 2>&1");
	if ($? != 0) {
		print "Error in openssl policy for $policy\n";
		system("cat $TMPFILE");
		print "ciphers: $tmp\n";
		exit 1;
	}
	unlink($TMPFILE);
}

exit 0;
