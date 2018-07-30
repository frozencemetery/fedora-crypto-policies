#!perl

require 5.000;
use strict;

use profiles::common;

my %protocol_map = (
        'SSL3.0'  => 'SSLv3',
        'TLS1.0'  => 'TLSv1',
        'TLS1.1'  => 'TLSv1.1',
        'TLS1.2'  => 'TLSv1.2',
        'TLS1.3'  => 'TLSv1.3',
        'DTLS1.0' => 'DTLSv1',
        'DTLS1.2' => 'DTLSv1.2'
);

sub generate_temp_policy() {
	my $confstr = '';

	$confstr .= 'Ciphers = ';
	# This includes the profile
	$confstr .= generate_ciphers(@_);
	$confstr .= "\n";

	# Unfortunately there is no practical way to set minimum DTLS version
	$confstr .= 'MinProtocol = ';
	$confstr .= $protocol_map{$min_tls_version};
	$confstr .= "\n";

	return $confstr;
}

sub test_temp_policy() {
}

1;
