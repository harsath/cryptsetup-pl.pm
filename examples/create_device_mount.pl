#!/usr/bin/perl
use warnings;
use strict;
use cryptsetup_pl;

my $user_name = "horrid_henry";
my $mount_root_path = "_mount_root";
my $crypt_devices_dir = "_crypt_devices";
my $crypt_keyfiles_dir = "_crypt_keyfiles";
my $luks_image_size = 20;

cryptsetup_pl::crypt_init(
	$user_name, $luks_image_size, $crypt_devices_dir, $crypt_keyfiles_dir,
	$mount_root_path
);

my $create_return = cryptsetup_pl::crypt_create_luks_device("secure password");
if($create_return){ print "crypt_create_luks_device returned True"; }
else{ print "crypt_create_luks_device returned False"; }
