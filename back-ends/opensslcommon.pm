package opensslcommon;

use strict;
use warnings;

BEGIN {
    require Exporter;
    our $VERSION = 1.00;
    our @ISA = qw(Exporter);
    our @EXPORT = qw(generate_ciphers generate_ciphersuites);
}

use profiles::common;

use File::Temp qw/ tempfile /;
use File::Copy;

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

# This limits policy definitions with following expectations:
# * disabling AES-256-GCM implies disabling all 256 bit AES
# * disabling AES-128-GCM implies disabling all 128 bit AES
# * disabling AES-256-CBC implies disabling all SHA256 HMAC ciphersuites
# * policy which disables CBC ciphersuites disables also SHA1 HMAC
# * disabling AES-128-CBC cannot be done separately from the above
# * SHA384 HMAC in TLS is always disabled

my %cipher_not_map = (
	'AES-256-CTR'       => '',
	'AES-128-CTR'       => '',
	'AES-256-GCM'  => '-AES256',
	'AES-128-GCM'  => '-AES128',
	'AES-256-CBC'  => '-SHA256',
	'AES-128-CBC'  => '',
	'CHACHA20-POLY1305'  => '-CHACHA20-POLY1305',
	'SEED-CBC'  => '-SEED',
	'IDEA-CBC'  => '!IDEA',
	'DES-CBC'   => '!DES',
	'RC4-40'    => '',
	'DES40-CBC' => '',
	'3DES-CBC'  => '-3DES',
	'RC4-128'   => '!RC4',
	'RC2-CBC'   => '!RC2',
	'NULL'      => '!eNULL:!aNULL'
);

my %key_exchange_map = (
	'RSA'       => 'kRSA',
	'ECDHE'     => 'kEECDH',
	'PSK'       => 'kPSK',
	'DHE-PSK'   => 'kDHEPSK',
	'DHE-RSA'   => 'kEDH',
	'DHE-DSS'   => '',
	'ECDHE-PSK' => 'kECDHEPSK'
);

my %key_exchange_not_map = (
	'ANON'       => '',
	'DH'         => '',
	'ECDH'       => '',
	'RSA'       => '-kRSA',
	'ECDHE'     => '-kEECDH',
	'DHE-RSA'   => '-aRSA',
	'DHE-DSS'   => '-aDSS',
	'PSK'       => '-kPSK',
	'DHE-PSK'   => '-kDHEPSK',
	'ECDHE-PSK' => '-kECDHEPSK'
);

my %mac_not_map = ( 'HMAC-MD5' => '!MD5',
	'HMAC-SHA1' => '-SHA1'
);

sub generate_ciphers(@) {
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

	# We cannot separate RSA strength from DH params.
	if ( $min_dh_size < 1023 || $min_rsa_size < 1023 ) {
		append('@SECLEVEL=0');
	}
	elsif ( $min_dh_size < 2048 || $min_rsa_size < 2048  ) {
		append('@SECLEVEL=1');
	}
	elsif ( $min_dh_size < 3072 || $min_rsa_size < 3072  ) {
		append('@SECLEVEL=2');
	}
	else {
		append('@SECLEVEL=3');
	}

	foreach (@key_exchange_list) {

		my $val = $key_exchange_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	foreach (@key_exchange_not_list) {
		my $val = $key_exchange_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	foreach (@tls_cipher_not_list) {
		my $val = $cipher_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	foreach (@mac_not_list) {
		my $val = $mac_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	# These ciphers are not necessary for any
	# policy level, and only increase the attack surface.
	append('-SHA384');
	append('-CAMELLIA');
	append('-ARIA');
	append('-AESCCM8');

	return $string;
}

my %ciphersuite_map = (
	'AES-256-GCM'  => 'TLS_AES_256_GCM_SHA384',
	'AES-128-GCM'  => 'TLS_AES_128_GCM_SHA256',
	'CHACHA20-POLY1305'  => 'TLS_CHACHA20_POLY1305_SHA256',
	'AES-128-CCM'  => 'TLS_AES_128_CCM_SHA256',
	'AES-128-CCM8'  => 'TLS_AES_128_CCM_8_SHA256',
);


sub generate_ciphersuites(@) {
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

	foreach (@tls_cipher_list) {
		my $val = $ciphersuite_map{$_};
		if ( defined($val) ) {
			append($val);
		}
	}

	return $string;
}

1;
