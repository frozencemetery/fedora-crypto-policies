#!perl

require 5.000;
use strict;

use profiles::common;
use File::Temp qw/ tempfile tmpnam /;

my $host_key_filename;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = shift;
	my $buf = shift;

	return if $arg eq '';

	if ( $print_init != 0 ) {
		$$buf .= ',';
	}
	$$buf .= $arg;
	$print_init = 1;
}

my %group_map = (
	'X448'    => '',
	'X25519'    => '', #dh31 - not in f28
	'SECP256R1' => 'dh19',
	'SECP384R1' => 'dh20',
	'SECP521R1' => 'dh21',
	'FFDHE-6144' => '',
	'FFDHE-1536' => 'dh5',
	'FFDHE-2048' => 'dh14',
	'FFDHE-3072' => 'dh15',
	'FFDHE-4096' => 'dh16',
	'FFDHE-8192' => 'dh18'
);

my %cipher_prf_map = (
	'AES-256-CBC-HMAC-SHA2-512'       => 'aes256-sha2_512',
	'AES-128-CBC-HMAC-SHA2-256'       => 'aes128-sha2_256',
	'AES-256-CBC-HMAC-SHA1'       => 'aes256-sha1',
	'AES-128-CBC-HMAC-SHA1'       => 'aes128-sha1',
	'AES-256-GCM-HMAC-SHA2-512'       => 'aes_gcm256-sha2_512',
	'AES-256-GCM-HMAC-SHA2-256'       => 'aes_gcm256-sha2_256',
#	'CHACHA20-POLY1305-SHA2-512' => 'chacha20_poly1305-sha2_512',
	'3DES-CBC-HMAC-SHA1'          => '3des-sha1',
);

my %protocol_map = (
	'IKEv1'  => 'ikev2=never',
	'IKEv2'  => 'ikev2=insist',
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
	my $tmp = '';

	my $nproto = @ike_protocol_list;
	if ($nproto == 1) {
		foreach (@ike_protocol_list) {
			my $val = $protocol_map{$_};
			if ( defined($val) ) {
				append($val, \$tmp);
			} else {
				print STDERR "libreswan: unknown: $_\n";
			}
		}
	} else {
		#if more than one protocols are enabled
		append('ikev2=permit', \$tmp);
	}

	$string .= "conn %default\n";
	if ($tmp ne '') {
		$string .= "\t$tmp\n";
	}
	$string .= "\tpfs=yes\n";

	$print_init = 0;
	$tmp = '';

	my $cipher;
	my $group;
	my $mac;
	my $combo;
	foreach (@group_list) {
		$group = $group_map{$_};
		if (!defined($group) || $group eq '') {
			next;
		}

		foreach (@cipher_list) {
			$cipher = $_;
			foreach (@mac_list) {
				$mac = $_;

				my $cm=$cipher."-".$mac;
				$combo = $cipher_prf_map{$cm};

				if (!defined($combo)) {
#					print STDERR "libreswan: unknown combo: $cipher-$mac\n";
					next;
				}

				append("${combo};${group}", \$tmp);
			}
		}
	}

	if ($tmp ne '') {
		$string .= "\tike=$tmp\n";
	}

	$print_init = 0;
	$tmp = '';
	foreach (@cipher_list) {
		$cipher = $_;
		foreach (@mac_list) {
			$mac = $_;

			my $cm=$cipher."-".$mac;
			$combo = $cipher_prf_map{$cm};

			if (!defined($combo)) {
				next;
			}

			if ($tmp !~ $combo) {
				append("${combo}", \$tmp);
			}
		}
	}

	if ($tmp ne '') {
		$string .= "\tesp=$tmp\n";
	}


	# we need restart here, since systemd needs to pick up a new command line options
	push(@{$reloadcmd_ref}, "test -e /usr/lib/systemd/system/ipsec.service && systemctl restart ipsec\n");

	return $string;
}

sub test_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $gstr    = shift(@_);

	if (-e "/usr/sbin/ipsec") {
		my ( $fh, $filename ) = tempfile();
		print $fh $gstr;
		close $fh;
		system("/usr/sbin/ipsec readwriteconf --config $filename >/dev/null");
		my $ret = $?;
		unlink($filename);

		if ( $ret != 0) {
			print STDERR "There is an error in libreswan generated policy\n";
			exit 1;
		}
	}
}

1;
