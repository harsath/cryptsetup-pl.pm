#!/usr/bin/perl
use warnings;
use strict;
use cryptsetup_pl;

my $cryptHashRef = {
	user_name => "horrid_henry",
	user_passphrase => "secure password",
	mount_root => "_mount_root",
	crypt_devices_dir => "_crypt_devices",
	path_to_keyfile_dir => "_crypt_keyfiles",
	luks_container_size => 100,
	mounting_first_time => 1,
	is_mounted => 0
};

cryptsetup_pl::crypt_init($cryptHashRef);

my $create_return = cryptsetup_pl::crypt_create_luks_device($cryptHashRef);

my $mount_return = cryptsetup_pl::crypt_mount_luks_device($cryptHashRef);

my $umount_return = cryptsetup_pl::crypt_unmount_crypt_device($cryptHashRef);
