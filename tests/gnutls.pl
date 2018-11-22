#!/usr/bin/perl

my $TMPFILE="out-gnutls.tmp";

my $libdir = "./back-ends";
use lib "./back-ends/";
use profiles::common;

print "Checking the GnuTLS configuration\n";

require "$libdir/gnutls.pl";

foreach my $policy (@profiles::common::policies) {

	my $tmp = generate_temp_policy($policy, "", $libdir);
	$tmp =~ s/SYSTEM=//g;
	chomp $tmp;

	system("gnutls-cli --priority '$tmp' -l >$TMPFILE 2>&1");
	if ($? == 0 && $policy eq 'EMPTY') {
		print "Error in gnutls empty policy ($policy)\n";
		print STDERR "gnutls-cli --priority '$tmp' -l\n";
		system("cat $TMPFILE 1>&2");
		exit 1;
	} elsif ($? != 0 && $policy ne 'EMPTY') {
		print "Error in gnutls policy for $policy\n";
		print STDERR "gnutls-cli --priority '$tmp' -l\n";
		system("cat $TMPFILE 1>&2");
		exit 1;
	}
	unlink($TMPFILE);
}

exit 0;
