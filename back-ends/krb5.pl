#!perl

require 5.000;
use strict;

use profiles::common;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = $_[0];
	return if $arg eq '';

	if ( $print_init != 0 ) {
		$string .= ' ';
	}
	$string .= $arg;
	$print_init = 1;
}

# Note that CTS mode is simply CBC with ciphertext stealing.
# DES support was removed upstream starting in 1.18.
# DES and 3DES support were removed downstream starting in krb5-1.17-31.fc31.
my %cipher_map = (
	'AES-256-CTR'       => '',
	'AES-128-CTR'       => '',
	'AES-256-GCM'	   => '',
	'AES-256-CCM'	   => '',
	'CHACHA20-POLY1305' => '',
	'CAMELLIA-256-GCM' => '',
	'AES-128-GCM'	   => '',
	'AES-128-CCM'	   => '',
	'CAMELLIA-128-GCM' => '',
	
	'AES-256-CBC'      => 'aes256-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192',
	'AES-128-CBC'      => 'aes128-cts-hmac-sha1-96 aes128-cts-hmac-sha256-128',
	'CAMELLIA-256-CBC' => 'camellia256-cts-cmac',
	'CAMELLIA-128-CBC' => 'camellia128-cts-cmac',
	'RC4-128'          => 'arcfour-hmac-md5',
	'DES-CBC'          => '',
	'CAMELLIA-128-CTS' => 'camellia128-cts-cmac',
	'3DES-CBC'         => '',
);

sub generate_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $libdir  = shift(@_);

	if (!-e "$libdir/profiles/$profile.pl") {
		print STDERR "Cannot file $profile.pl in $libdir/profiles\n";
		exit 1;
	}
	do "$libdir/profiles/$profile.pl";

	$string = "[libdefaults]\n";
	$print_init = 0;

	$string .= "permitted_enctypes = ";
	foreach (@cipher_list) {
		my $val = $cipher_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "krb5: unknown: $_\n";
		}
	}

	$string .= "\n";

	# By default libkrb5 sets the min_bits to 2048, don't
	# go lower than that.
	if ($min_dh_size > 2048) {
#		$string .= "pkinit_dh_min_bits=$min_dh_size\n";
#		krb5.conf only accepts 2048 or 4096
		$string .= "pkinit_dh_min_bits=4096\n";
	}

	return $string;
}

sub test_temp_policy() {
	return;
}

1;
