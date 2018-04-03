#!perl

require 5.000;
use strict;

use profiles::common;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = $_[0];
	return if ( $arg eq '' );
	$string .= $arg;
	$string .= ";\n";
}

my %sign_not_map = (
	'RSA-MD5'  => 'RSAMD5',
	'DSA-SHA1' => 'DSA',
	'ECDSA-SHA1' => '',
	'RSA-SHA1' => "RSASHA1;\nNSEC3RSASHA1"
);

my %hash_not_map = (
	'MD5'      => '',
	'SHA1'     => 'SHA-1',
	'GOST'     => 'GOST',
	'SHA2-256' => 'SHA-256',
	'SHA2-384' => 'SHA-384'
);

sub generate_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $libdir  = shift(@_);
	my $reloadcmd_ref = shift(@_);

	if (!-e "$libdir/profiles/$profile.pl") {
		print STDERR "Cannot file $profile.pl in $libdir/profiles\n";
		exit 1;
	}
	do "$libdir/profiles/$profile.pl";

	$string = '';
	$print_init = 0;
	$string .= "disable-algorithms \".\" {\n";

	foreach (@sign_not_list) {
		my $val = $sign_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "bind: unknown: $_\n";
		}
	}

	$string .= "};\n";

	$string .= "disable-ds-digests \".\" {\n";

	foreach (@hash_not_list) {
		my $val = $hash_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "bind: unknown: $_\n";
		}
	}

	$string .= "};\n";

	push(@{$reloadcmd_ref}, "systemctl is-enabled bind && systemctl reload-or-restart bind\n");

	return $string;
}

sub test_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $gstr    = shift(@_);

	if (-e "/usr/sbin/named-checkconf") {
		my ( $fh, $filename ) = tempfile();
		print $fh "options {\n";
		print $fh $gstr;
		print $fh "\n};\n";
		close $fh;
		system("/usr/sbin/named-checkconf $filename");
		my $ret = $?;
		unlink($filename);

		if ( $ret != 0 ) {
			print STDERR "There is an error in bind generated policy\n";
			exit 1;
		}
	}
}

1;
