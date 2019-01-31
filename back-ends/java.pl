#!perl

require 5.000;
use strict;

use profiles::common;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = $_[0];
	return if ( $arg eq '' );

	if ( $print_init != 0 ) {
		$string .= ', ';
	}
	$string .= $arg;
	$print_init = 1;
}

sub append_reset {
	$string .= "\n";
	$print_init = 0;
}

my %hash_not_map = (
	'MD2'  => 'MD2',
	'MD5'  => 'MD5',
	'SHA1' => 'SHA1',
	'SHA2-224' => 'SHA224',
	'SHA2-256' => 'SHA256',
	'SHA2-384' => 'SHA384',
	'SHA2-512' => 'SHA512',
	'SHA3-256' => 'SHA3_256',
	'SHA3-384' => 'SHA3_384',
	'SHA3-512' => 'SHA3_512',
	'GOST' => ''
);

my %cipher_not_map = (
	'AES-256-CTR'       => '',
	'AES-128-CTR'       => '',
	'CHACHA20-POLY1305' => '',
	'CAMELLIA-256-GCM' => '',
	'CAMELLIA-128-GCM' => '',
	'CAMELLIA-256-CBC' => '',
	'CAMELLIA-128-CBC' => '',
	'AES-256-CBC' => 'AES_256_CBC',
	'AES-128-CBC' => 'AES_128_CBC',
	'AES-256-GCM' => 'AES_256_GCM',
	'AES-128-GCM' => 'AES_128_GCM',
	'AES-256-CCM' => 'AES_256_CCM',
	'AES-128-CCM' => 'AES_128_CCM',
	'RC4-128'   => 'RC4_128',
	'RC4-40'    => 'RC4_40',
	'RC2-CBC'   => 'RC2',
	'DES-CBC'   => 'DES_CBC',
	'DES40-CBC' => 'DES40_CBC',
	'3DES-CBC'  => '3DES_EDE_CBC',
	'SEED-CBC'  => '',
	'IDEA-CBC'  => '',
	'NULL'      => ''
);

my %cipher_legacy_map = (
	'RC4-128'   => 'RC4_128',
	'3DES-CBC'  => '3DES_EDE_CBC',
);

my %key_exchange_not_map = (
	'EXPORT' => 'RSA_EXPORT, DHE_DSS_EXPORT, DHE_RSA_EXPORT, DH_DSS_EXPORT, DH_RSA_EXPORT',
	'DH'         => 'DH_RSA, DH_DSS',
	'ANON'       => 'DH_anon, ECDH_anon',
	'RSA'        => 'TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256',
	'DHE-RSA'      => 'DHE_RSA',
	'DHE-DSS'      => 'DHE_DSS',
	'ECDHE'      => 'ECDHE',
	'ECDH'       => 'ECDH',
	'PSK'        => '',
	'DHE-PSK'    => '',
	'ECDHE-PSK'  => ''
);

# we handle signature algorithms via disabled hashes
my %sign_not_map = (
	'DSA-SHA1' => 'DSA',
	'RSA-SHA1' => '',
	'ECDSA-SHA1' => '',
	'RSA-MD5'  => ''
);

my %protocol_not_map = (
	'SSL2.0' => 'SSLv2',
	'SSL3.0' => 'SSLv3',
	'TLS1.0' => 'TLSv1',
	'TLS1.1' => 'TLSv1.1',
	'TLS1.2' => 'TLSv1.2',
	'DTLS1.0' => '',
	'DTLS1.2' => ''
);

my %mac_not_map = (
	'AEAD'	=> '',
	'HMAC-MD5' => 'HmacMD5',
	'HMAC-SHA1' => 'HmacSHA1',
	'HMAC-SHA2-256' => 'HmacSHA256',
	'HMAC-SHA2-384' => 'HmacSHA384',
	'HMAC-SHA2-512' => 'HmacSHA512',
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

	$string .= "jdk.tls.ephemeralDHKeySize=$min_dh_size\n";

	$string .= "jdk.certpath.disabledAlgorithms=";
	append("MD2");

	foreach (@hash_not_list) {
		my $val = $hash_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "java: unknown: $_\n";
		}
	}

	foreach (@sign_not_list) {
		my $val = $sign_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
#		else {
#			print STDERR "java: unknown: $_\n";
#		}
	}

	append("RSA keySize < $min_rsa_size");

	append_reset();
	$string .= "jdk.tls.disabledAlgorithms=";
	append("DH keySize < $min_dh_size");

	foreach (@protocol_not_list) {
		my $val = $protocol_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "java: unknown: $_\n";
		}
	}

	foreach (@key_exchange_not_list) {
		my $val = $key_exchange_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "java: unknown: $_\n";
		}
	}

	foreach (@cipher_not_list) {
		my $val = $cipher_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "java: unknown: $_\n";
		}
	}

	foreach (@mac_not_list) {
		my $val = $mac_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "java: unknown: $_\n";
		}
	}

	append_reset();
	$string .= "jdk.tls.legacyAlgorithms=";

	foreach (@cipher_list) {
		my $val = $cipher_legacy_map{$_};
		if ( defined($val) ) {
			append($val);
		}
	}

	$string .= "\n";
	return $string;
}

sub test_temp_policy() {
	return;
}

1;
