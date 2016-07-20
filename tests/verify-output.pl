#!/usr/bin/perl

use strict;
use warnings;

my $libdir = "back-ends/";
use lib "back-ends/";

my @profiles = ("DEFAULT", "FUTURE", "LEGACY");
my @modules = ("gnutls", "gnutls28", "openssl", "bind", "java", "krb5", "nss");
my ($mod, $contents, $profile);
my @reloadcmds = ();

foreach $mod (@modules) {
	require "$libdir/$mod.pl";
	my $tmp = '';

    foreach $profile (@profiles) {

	$tmp = generate_temp_policy($profile, 0, $libdir, \@reloadcmds);
	$contents = '';

	if (open my $fh, '<', "tests/outputs/$profile-$mod.txt") {
    	    $/ = undef;
    	    $contents = <$fh>;
    	    close $fh;
    	    $/ = "\n";
        } else {
            open my $fh, '>', "tests/outputs/$profile-$mod.txt";
            print $fh $tmp;
            close $fh;
        }

	if ($tmp ne $contents) {
	    print "Error in the contents of $profile-$mod.txt\n";
	    exit 1;
	}

	test_temp_policy($profile, 0, $tmp);
    }
}

exit 0;
