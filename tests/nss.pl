#!/usr/bin/perl

my $TMPFILE="policy-nss.tmp";
my $RESULTFILE="result-nss.tmp";

my $libdir = "./back-ends";
use lib "./back-ends/";
use profiles::common;
use File::Which qw(which);

print "Checking the NSS configuration\n";

require "$libdir/nss.pl";

foreach my $policy (@profiles::common::policies) {

	my $tmp = generate_temp_policy($policy, "", $libdir);
	my $tool = which "nss-policy-check";

	# Temporarily skip the check if DSA keyword is present
	if (index($tmp, ":DSA:") != -1) {
		next;
	}

	if ($policy ne 'EMPTY' and $tool ne undef) {
		open my $file, '>', $TMPFILE or die $!;
		print $file $tmp;
		close $file;

		system("nss-policy-check $TMPFILE >$RESULTFILE 2>&1") ;
		if ($? != 0) {
			print "Error in NSS policy for $policy\n";
			system("cat $TMPFILE 1>&2");
			system("cat $RESULTFILE 1>&2");
			exit 1;
		}
		unlink($TMPFILE);
		unlink($RESULTFILE);
	}
}

exit 0;
