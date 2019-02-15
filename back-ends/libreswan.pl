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
	'X25519'    => '',
# Disabled for now as it cannot be prioritized over others
#	'X25519'    => 'dh31',
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

my %cipher_map = (
	'AES-256-CBC'       => 'aes256',
	'AES-128-CBC'       => 'aes128',
	'AES-256-GCM'       => 'aes_gcm256',
	'AES-128-GCM'       => 'aes_gcm128',
	'CHACHA20-POLY1305' => 'chacha20_poly1305',
# Unused for IKEv2
#	'3DES-CBC'          => '3des',
);

my %cipher_prf_map = (
	'AES-256-CBC-HMAC-SHA2-512'       => 'sha2_512',
	'AES-256-CBC-HMAC-SHA2-256'       => 'sha2_256',
	'AES-128-CBC-HMAC-SHA2-256'       => 'sha2_256',
# Not needed for IKEv2
#	'AES-256-CBC-HMAC-SHA1'           => 'sha1',
#	'AES-128-CBC-HMAC-SHA1'           => 'sha1',
	'AES-256-GCM-HMAC-SHA2-512'       => 'sha2_512',
	'AES-256-GCM-HMAC-SHA2-256'       => 'sha2_256',
	'AES-128-GCM-HMAC-SHA2-512'       => 'sha2_512',
	'AES-128-GCM-HMAC-SHA2-256'       => 'sha2_256',
	'CHACHA20-POLY1305-HMAC-SHA2-512' => 'sha2_512',
	'CHACHA20-POLY1305-HMAC-SHA2-256' => 'sha2_256',
#	'3DES-CBC-HMAC-SHA1'              => 'sha1',
);

my %cipher_mac_map = (
	'AES-256-CBC-HMAC-SHA2-512'       => 'sha2_512',
	'AES-256-CBC-HMAC-SHA2-256'       => 'sha2_256',
	'AES-128-CBC-HMAC-SHA2-256'       => 'sha2_256',
	'AES-256-CBC-HMAC-SHA1'       => 'sha1',
	'AES-128-CBC-HMAC-SHA1'       => 'sha1',
	'AES-256-GCM-AEAD'            => '',
	'AES-128-GCM-AEAD'            => '',
	'CHACHA20-POLY1305-AEAD'      => '',
#	'3DES-CBC-HMAC-SHA1'          => '3des-sha1',
);

my %protocol_map = (
	'IKEv1'  => 'ikev2=never',
	'IKEv2'  => 'ikev2=insist',
);

my %mac_ike_prio_map = (
	'AEAD' => 0,
	'HMAC-SHA2-512' => 1,
	'HMAC-SHA2-256' => 2,
	'HMAC-SHA1' => 3,
);

my %mac_esp_prio_map = (
	'AEAD' => 0,
	'HMAC-SHA2-512' => 1,
	'HMAC-SHA1' => 2,
	'HMAC-SHA2-256' => 3,
);

my %mac_prio_map;

sub compare {
	my $aprio = $mac_prio_map{$a};
	my $bprio = $mac_prio_map{$b};

	if (!defined($aprio)) {
		$aprio = 99;
	}
	if (!defined($bprio)) {
		$bprio = 99;
	}
	if ($aprio < $bprio) {
		return -1;
	} elsif ($aprio == $bprio) {
		return 0;
	} else {
		return 1;
	}
}

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
	my $cm;
	my $group;
	my $mac;
	my $mm;
	my $combo;

	%mac_prio_map = %mac_ike_prio_map;
	my @sorted_mac_list = sort compare @mac_list;


	foreach (@cipher_list) {
		$cipher = $_;
		$cm = $cipher_map{$cipher};
		if (!defined($cm)) {
#			print STDERR "libreswan: unknown cipher: $cipher\n";
			next;
		}
		$combo = $cm."-";
		foreach (@sorted_mac_list) {
			$mac = $_;

			$mm = $cipher_prf_map{$cipher."-".$mac};

			if (!defined($mm)) {
#				print STDERR "libreswan: unknown combo: $cipher-$mac\n";
				next;
			}

			$combo = $combo.$mm."+";
		}

		my $lastc = substr($combo, -1);
		if ($lastc eq "-") {
			next;
		}
		# Replace the last + with -
		substr($combo, -1) = "-";
		foreach (@group_list) {
			$group = $group_map{$_};
			if (!defined($group) || $group eq '') {
				next;
			}
			$combo = $combo.$group."+";
		}
		substr($combo, -1) = '';
		append("${combo}", \$tmp);
	}

	if ($tmp ne '') {
		$string .= "\tike=$tmp\n";
	}

	%mac_prio_map = %mac_esp_prio_map;
	@sorted_mac_list = sort compare @mac_list;

	$print_init = 0;
	$tmp = '';
	foreach (@cipher_list) {
		$cipher = $_;
		$cm = $cipher_map{$cipher};
		if (!defined($cm)) {
#			print STDERR "libreswan: unknown cipher: $cipher\n";
			next;
		}
		$combo = $cm."-";
		foreach (@sorted_mac_list) {
			$mac = $_;

			$mm = $cipher_mac_map{$cipher."-".$mac};

			if (!defined($mm)) {
				next;
			}

			if ($mm eq '') {
				# Special handling for AEAD
				substr($combo, -1) = '+';
			} else {
				$combo = $combo.$mm."+";
			}
		}

		my $lastc = substr($combo, -1);
		if ($lastc eq "-") {
			next;
		}
		substr($combo, -1) = '';
		append("${combo}", \$tmp);
	}

	if ($tmp ne '') {
		$string .= "\tesp=$tmp\n";
	}


	# we need restart here, since systemd needs to pick up a new command line options
	push(@{$reloadcmd_ref}, "systemctl try-restart ipsec.service 2>/dev/null || :\n");

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
