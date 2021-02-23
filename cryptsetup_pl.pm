package cryptsetup_pl;
use Digest::MD5 qw/md5_hex/;
use Exporter;

@ISA = qw/Exporter/;
@EXPORT = qw/
		crypt_init crypt_create_luks_device crypt_mount_crypt_device crypt_get_uuid_device
		crypt_create_block_device crypt_get_username_hash crypt_check_already_mount
		crypt_nuke_luks_device crypt_unmount_crypt_device crypt_decrypt_keyfile
	   /;

my $user_name;
my $path_to_luks_devices;
my $path_to_user_luks_device;
my $path_to_keyfile_dir;
my $key_file_out_fullpath = "/tmp/$user_hash";
my $user_hash;

my $openssl = `which openssl`; _is_defined($openssl, "[ERROR] openssl not found");
my $cryptsetup = `which cryptsetup`; _is_defined($cryptsetup, "[ERROR] cryptsetup not found");
my $shred = `which shred`; _is_defined($shred, "[ERROR] shred not found");
my $dd = `which dd`; _is_defined($dd, "[ERROR] dd not found");

sub crypt_init{
	($user_name, $path_to_luks_devices, $path_to_keyfile_dir) = @_;
	$user_hash = crypt_get_username_hash($user_name);
	$path_to_user_luks_device = "$path_to_luks_devices/".crypt_get_username_hash();
	true;
}

sub crypt_create_luks_device{

}

sub crypt_mount_crypt_device{
	my ($device_name, $device_path) = @_;
}

sub crypt_get_uuid_device{

}

sub crypt_create_block_device{

}

sub crypt_get_username_hash{
	md5_hex($_);
}

sub crypt_check_already_mount{

}

sub crypt_get_keyfile_out_path{
	$key_file_out_fullpath;
}

sub crypt_get_keyfile_in_path{
	$key_file_in_fullpath;
}

sub crypt_get_user_luks_device_path{
	$path_to_user_luks_device;
}

sub crypt_nuke_luks_device_and_key{
	`$shred -uzn 10 $path_to_user_luks_device`;
	`$shred -uzn 10 $key_file_in_fullpath`;
	 crypt_nuke_cleartext_keyfile();
	 true;
}

sub crypt_unmount_crypt_device{

}

sub crypt_decrypt_keyfile{
	my ($user_passphrase) = @_;
	my $iter = 100000;
	if(-e $key_file_out_fullpath){
		`$shred -uzn 10 $key_file_out_fullpath`;
		`touch $key_file_out_fullpath && chmod 700 $key_file_out_fullpath`;
	}
	$key_file_in_fullpath = "$path_to_keyfile_dir/$user_hash";

	unless(-e $key_file_in_fullpath){
		print "No such keyfile";
		return false;
	}

	`$openssl enc -d -aes-256-cbc -pbkdf2 -md sha512 -in $key_file_in_fullpath -out $key_file_out_fullpath`;
	true;
}

sub crypt_nuke_cleartext_keyfile{
	if(-e $key_file_out_fullpath)
	{ `$shred -uzn 10 $key_file_out_fullpath`; }
}

sub _is_defined{
	my ($var_to_check, $error_msg) = @_;
	unless(defined $var_to_check && $var_to_check ne '')
	{ print $error_msg; exit 2; }
}

sub _generate_keyfile{
	my $key_passphrase = @_;
	unless(-e $key_file_in_fullpath){
		`touch $key_file_out_fullpath && chmod 700 $key_file_out_fullpath`;
		`$dd bs=512 count=1 if=/dev/urandom of=$key_file_out_fullpath`;
		`$openssl enc -e -aes-256-cbc -md sha512 -pbkdf2 -iter 100000 -salt -in $key_file_out_fullpath
		 -out $key_file_in_fullpath -pass pass:$key_passphrase`;
		 crypt_nuke_cleartext_keyfile();
	}else{
		`$shred -uzn 10 $key_file_in_fullpath`;
		_generate_keyfile();
	}
}

1;
