#!/bin/sh

set -e

umask 022

: ${top_srcdir=..}

progname="$0"
script="$top_srcdir/update-crypto-policies"
testdir=`mktemp -d -t "update-crypto-policies.XXXXXXXX"`
trap 'rm -rf $testdir' 0

profile_dir="$testdir/profile"
mkdir "$profile_dir"

base_dir="$testdir/base"
mkdir "$base_dir"
mkdir "$base_dir/local.d"

(cd "$top_srcdir" ; ./generate-policies.pl "$profile_dir" 2>/dev/null)
echo DEFAULT > "$profile_dir/default-config"
echo DEFAULT > "$base_dir/config"

check_symlink() {
	for profile_file in "$profile_dir"/"$1"/*.txt; do
		profile_base=$(basename "$profile_file")
		config_file="$base_dir/back-ends/${profile_base%%.txt}.config"
		test -h "$config_file" || {
			echo "$progname: $config_file is not a symlink"
			exit 1
		}
		target_file=$(readlink "$config_file")
		test "$target_file" = "$profile_file" || {
			echo "$progname: $target_file is not a symlink to $profile_file"
			exit 1
		}
	done
}

echo "$0: checking if default profile is properly selected"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-check --no-reload
check_symlink DEFAULT

echo "$0: checking if switching to other profile works"
profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-check --no-reload --set LEGACY
check_symlink LEGACY

check_local() {
	profile_file="$profile_dir"/"$1"/"$2".txt
	config_file="$base_dir/back-ends/$2.config"
	test -f "$config_file" || {
		echo "$progname: $config_file is not a regular file"
		exit 1
	}
	cat "$profile_file" "$base_dir/local.d"/"$2"-*.config > "$testdir/merged"
	cmp "$config_file" "$testdir/merged" || {
		echo "$progname: $config_file is not properly merged"
		exit 1
	}
}

echo "$0: checking if local.d works"

cat > "$base_dir/local.d/nss-foo.config" <<EOF
name=foo
library=foo.so
EOF

cat > "$base_dir/local.d/nss-bar.config" <<EOF
name=bar
library=bar.so
EOF

profile_dir="$profile_dir" base_dir="$base_dir" "$script" --no-check --no-reload --set DEFAULT
check_local DEFAULT nss
