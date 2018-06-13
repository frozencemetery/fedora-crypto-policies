
#!perl

# For gnutls 3.6.0 or later

require 5.000;
use strict;

use File::Temp qw/ tempfile /;
use File::Copy;

use profiles::common;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = $_[0];
	return if $arg eq '';

	if ( $print_init != 0 ) {
		$string .= ':';
	}
	$string .= $arg;
	$print_init = 1;
}

my %mac_map = (
	'AEAD'          => '+AEAD',
	'HMAC-SHA1'     => '+SHA1',
	'HMAC-MD5'      => '+MD5',
	'HMAC-SHA2-256' => '+SHA256',
# intentionally leaving out; there is no particular
# reason for a server or client to enable these hashes
# by default, as they are compatibility hashes which
# only apply to broken ciphersuites with CBC.
	'HMAC-SHA2-384' => '',
	'HMAC-SHA2-512' => ''
);

my %group_map = (
	'X448'    => '',
	'X25519'    => '+GROUP-X25519',
	'SECP256R1' => '+GROUP-SECP256R1',
	'SECP384R1' => '+GROUP-SECP384R1',
	'SECP521R1' => '+GROUP-SECP521R1',
	'FFDHE-6144' => '',
	'FFDHE-2048' => '+GROUP-FFDHE2048',
	'FFDHE-3072' => '+GROUP-FFDHE3072',
	'FFDHE-4096' => '+GROUP-FFDHE4096',
	'FFDHE-8192' => '+GROUP-FFDHE8192',
);

my %sign_not_map = (
	'RSA-MD5' => '-SIGN-RSA-MD5',
	'RSA-SHA1' => '-SIGN-RSA-SHA1',
	'DSA-SHA1' => '-SIGN-DSA-SHA1',
	'ECDSA-SHA1' => '-SIGN-ECDSA-SHA1',
	'RSA-SHA2-224' => '-SIGN-RSA-SHA224',
	'DSA-SHA2-224' => '-SIGN-DSA-SHA224',
	'ECDSA-SHA2-224' => '-SIGN-ECDSA-SHA224',
	'RSA-SHA2-256' => '-SIGN-RSA-SHA256',
	'DSA-SHA2-256' => '-SIGN-DSA-SHA256',
	'ECDSA-SHA2-256' => '-SIGN-ECDSA-SHA256',
	'RSA-SHA2-384' => '-SIGN-RSA-SHA384',
	'DSA-SHA2-384' => '-SIGN-DSA-SHA384',
	'ECDSA-SHA2-384' => '-SIGN-ECDSA-SHA384',
	'RSA-SHA2-512' => '-SIGN-RSA-SHA512',
	'DSA-SHA2-512' => '-SIGN-DSA-SHA512',
	'ECDSA-SHA2-512' => '-SIGN-ECDSA-SHA512',
	'RSA-PSS-SHA2-256' => '-SIGN-RSA-PSS-SHA256',
	'RSA-PSS-SHA2-384' => '-SIGN-RSA-PSS-SHA384',
	'RSA-PSS-SHA2-512' => '-SIGN-RSA-PSS-SHA512',
	'EDDSA-ED25519' => '-SIGN-EDDSA-ED25519'
	);

my %cipher_map = (
	'AES-256-CTR'       => '',
	'AES-128-CTR'       => '',
	'AES-256-GCM'       => '+AES-256-GCM',
	'AES-128-GCM'       => '+AES-128-GCM',
	'AES-256-CCM'       => '+AES-256-CCM',
	'AES-128-CCM'       => '+AES-128-CCM',
	'AES-256-CBC'       => '+AES-256-CBC',
	'AES-128-CBC'       => '+AES-128-CBC',
# Intentionally leaving out Camellia as we now have
# CHACHA20 as a back-up cipher, and these ciphersuites
# are not available under TLS1.3, and enabling them
# would make ciphersuite selection quite confusing.
	'CAMELLIA-256-GCM'  => '',
	'CAMELLIA-128-GCM'  => '',
	'CAMELLIA-256-CBC'  => '',
	'CAMELLIA-128-CBC'  => '',
	'CHACHA20-POLY1305' => '+CHACHA20-POLY1305',
	'3DES-CBC'          => '+3DES-CBC',
	'RC4-128'	    => '+ARCFOUR-128'
);

my %key_exchange_map = (
	'RSA'       => '+RSA',
	'ECDHE'     => '+ECDHE-RSA:+ECDHE-ECDSA',
	'DHE-RSA'   => '+DHE-RSA',
	'DHE-DSS'   => '+DHE-DSS',
	'PSK'       => '',
	'DHE-PSK'   => '',
	'ECDHE-PSK' => ''
);

my %protocol_map = (
	'SSL3.0'  => '+VERS-SSL3.0',
	'TLS1.0'  => '+VERS-TLS1.0',
	'TLS1.1'  => '+VERS-TLS1.1',
	'TLS1.2'  => '+VERS-TLS1.2',
	'DTLS1.0' => '+VERS-DTLS1.0',
	'DTLS1.2' => '+VERS-DTLS1.2',
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

	$string = '';
	$print_init = 0;
	append('SYSTEM=NONE');

	foreach (@mac_list) {
		my $val = $mac_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "gnutls: unknown: $_\n";
		}
	}

	foreach (@group_list) {
		my $val = $group_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "gnutls: unknown: $_\n";
		}
	}

	if (@sign_list) {
		append("+SIGN-ALL");
		foreach (@sign_not_list) {
			my $val = $sign_not_map{$_};
			if ( defined($val) ) {
				append($val);
			}
			else {
				print STDERR "gnutls: unknown: $_\n";
			}
		}
	}

	foreach (@tls_cipher_list) {
		my $val = $cipher_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "gnutls: unknown: $_\n";
		}
	}

	foreach (@key_exchange_list) {
		my $val = $key_exchange_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "gnutls: unknown: $_\n";
		}
	}

	foreach (@protocol_list) {
		my $val = $protocol_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "gnutls: unknown: $_\n";
		}
	}

	append('+COMP-NULL');

	#we cannot separate RSA strength from DH params
	if ( $min_dh_size <= 768 || $min_rsa_size <= 768 ) {
		append('%PROFILE_VERY_WEAK');
	}
	elsif ( $min_dh_size <= 1024 || $min_rsa_size <= 1024 ) {
		append('%PROFILE_LOW');
	}
	elsif ( $min_dh_size <= 2048 || $min_rsa_size <= 2048 ) {
		append('%PROFILE_MEDIUM');
	}
	elsif ( $min_dh_size <= 3072 || $min_rsa_size <= 3072 ) {
		append('%PROFILE_HIGH');
	}
	elsif ( $min_dh_size <= 8192 || $min_rsa_size <= 8192 ) {
		append('%PROFILE_ULTRA');
	}
	elsif ( $min_dh_size <= 15360 || $min_rsa_size <= 15360 ) {
		append('%PROFILE_FUTURE');
	}
	else {
		exit 1;
	}

	$string .= "\n";
	return $string;
}

sub test_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $gstr    = shift(@_);

	if (-e "/usr/bin/gnutls-cli") {
		my ( $fh, $filename ) = tempfile();
		print $fh $gstr;
		close $fh;
		system(
"/usr/bin/gnutls-cli -l --priority `cat $filename|sed 's/SYSTEM=//g'|tr --delete '\n'` >/dev/null"
		);
		my $ret = $?;
		unlink($filename);

		if ( $ret != 0 ) {
			print STDERR "There is an error in gnutls generated policy\n";
			exit 1;
		}
	}
}

1;
