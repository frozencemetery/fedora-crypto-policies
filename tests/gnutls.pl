#!/usr/bin/perl

my $TMPFILE="out-gnutls.tmp";

my $libdir = "./back-ends";
use lib "./back-ends/";
use profiles::common;

require "$libdir/gnutls.pl";

foreach my $policy (@profiles::common::policies) {

	my $tmp = generate_temp_policy($policy, "", $libdir);
	$tmp =~ s/SYSTEM=//g;
	chomp $tmp;

	system("gnutls-cli --priority '$tmp' -l >$TMPFILE 2>&1");
	if ($? != 0) {
		print "Error in gnutls policy for $policy\n";
		print "gnutls-cli --priority '$tmp' -l\n";
		system("cat $TMPFILE");
		exit 1;
	}
	unlink($TMPFILE);
}

exit 0;
