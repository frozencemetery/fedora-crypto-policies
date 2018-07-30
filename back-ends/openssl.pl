#!perl

require 5.000;
use strict;

use opensslcommon;

use File::Temp qw/ tempfile /;
use File::Copy;

sub generate_temp_policy() {
	my $libdir = $_[2];

	return generate_ciphers(@_);
}

sub test_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $gstr    = shift(@_);

	if (-e "/usr/bin/openssl") {
		my ( $fh, $filename ) = tempfile();
		print $fh $gstr;
		close $fh;
		system("openssl ciphers `cat $filename` >/dev/null");
		my $ret = $?;

		if ( $ret != 0 ) {
			unlink($filename);
			print STDERR "There is an error in openssl generated policy\n";
			print STDERR "policy: $gstr\n";
			exit 1;
		}

		my $res = qx(openssl ciphers `cat $filename`);
		unlink($filename);

		if ($res =~ /NULL|ADH/ ) {
			print STDERR "There is NULL or ADH in openssl generated policy\n";
			print STDERR "policy: $gstr\n";
			exit 1;
		}
	}
}

1;
