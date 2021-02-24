package cryptsetup_pl;
use Digest::MD5 qw/md5_hex/;
use Exporter;

@ISA = qw/Exporter/;
@EXPORT = qw/
		crypt_init crypt_create_luks_device crypt_mount_crypt_device crypt_get_uuid_device
		crypt_get_username_hash crypt_check_already_mount
		crypt_nuke_luks_device crypt_unmount_crypt_device crypt_decrypt_keyfile
	   /;

my $user_name;
my $path_to_luks_devices;
my $path_to_user_luks_device;
my $path_to_user_keyfile;
my $path_to_keyfile_dir;
my $cleartext_tmp_keyfile_path;
my $user_hash;
my $mount_root;
my $luks_container_size; #value in MB
my $is_mounted = false;

chomp(my $openssl = `which openssl`); _is_defined($openssl, "[ERROR] openssl not found");
chomp(my $cryptsetup = `which cryptsetup`); _is_defined($cryptsetup, "[ERROR] cryptsetup not found");
chomp(my $shred = `which shred`); _is_defined($shred, "[ERROR] shred not found");
chomp(my $dd = `which dd`); _is_defined($dd, "[ERROR] dd not found");
chomp(my $blkid = `which blkid`); _is_defined($blkid, "[ERROR] blkid not found");

=begin crypt_init_args
	Args:	1. username, 2. size of LUKS container, 3. path to root LUKS devices dir,
	        4. path to root keyfiles dir, 5. path to mount root of LUKS devices
=cut
sub crypt_init{
	($user_name, $luks_container_size, $path_to_luks_devices, $path_to_keyfile_dir, $mount_root) = @_;
	$user_hash = crypt_get_username_hash($user_name);
	$path_to_user_luks_device = "$path_to_luks_devices/$user_hash.bin";
	$path_to_user_keyfile = "$path_to_keyfile_dir/$user_hash.key";
	$cleartext_tmp_keyfile_path = "/tmp/$user_hash.key";
	true;
}

=begin crypt_create_luks_device
	Args:	1. passphrase for the keyfile which will be encrypted by AES-256-CBC and stored on server
=cut
sub crypt_create_luks_device{
	my $keyfile_passphrase = shift;
	if(-e $path_to_user_luks_device)
	{ return false; }
	`$dd if=/dev/zero of=$path_to_user_luks_device bs=1M count=$luks_container_size 1>/dev/null 2>&1`;
	_generate_keyfile($keyfile_passphrase);
	`sudo $cryptsetup -q luksFormat $path_to_user_luks_device $cleartext_tmp_keyfile_path`;
	crypt_nuke_cleartext_keyfile();
	true;
}

=begin crypt_mount_crypt_device
	Args:	1. Is the LUKS device/image mounting for first time? Because If so, we need to
	 	   create a File-System on the fresh LUKS block device.
=cut
sub crypt_mount_luks_device{
	my ($mounting_first_time, $keyfile_passphrase) = @_;
	if(!(-e $path_to_user_luks_device) && !(-e $path_to_user_keyfile) && 
	       `file $path_to_user_luks_device | awk '{print \$2}'` ne "LUKS")
	{ return false; }

	crypt_decrypt_keyfile($keyfile_passphrase);
	unless($mounting_first_time){
		`sudo $cryptsetup -q luksOpen $path_to_user_luks_device $user_hash --key-file $cleartext_tmp_keyfile_path`;
	}else{
		`sudo $cryptsetup -q luksOpen $path_to_user_luks_device $user_hash --key-file $cleartext_tmp_keyfile_path`;
		`sudo mkfs.ext4 /dev/mapper/$user_hash 1>/dev/null 2>&1`;
	}
	crypt_nuke_cleartext_keyfile();

	my $user_mapper_mount_path = "$mount_root/$user_hash";
	unless(-d $user_mapper_mount_path)
	{ `mkdir -p $user_mapper_mount_path`; }
	`sudo mount /dev/mapper/$user_hash $user_mapper_mount_path`; $is_mounted = true;
	unless(_is_defined($ENV{USER}), "[ERROR] \$ENV{USER} not found/undefined")
	{ return false; }
	`sudo chown -R $ENV{USER} $user_mapper_mount_path`;
	true;
}

=begin crypt_get_uuid_device
	Returns the UUID if the LUKS block device if it is mounted under device mapper
=cut
sub crypt_get_uuid_device{
	if($is_mounted)
	{ return `$blkid /dev/mapper/$user_hash | awk '{print \$2}'`; }
	return "";
}

=begin crypt_get_username_hash
	Arg:	1. Plain user name string
	Returns the MD5-digest of the given user name's MD5-digest;
=cut
sub crypt_get_username_hash{
	md5_hex($_);
}

=begin crypt_check_already_mount
	Returns true if the LUKS device is hot/mounted if not, returns false
=cut
sub crypt_check_already_mount{
	$is_mounted;
}

=begin crypt_get_keyfile_out_path
=cut
sub crypt_get_keyfile_out_path{
	$cleartext_tmp_keyfile_path;
}

sub crypt_get_keyfile_in_path{
	$path_to_user_keyfile;
}

sub crypt_get_user_luks_device_path{
	$path_to_user_luks_device;
}

sub crypt_get_user_dir_mount_path{
	"$mount_root/$user_hash";
}

sub crypt_nuke_luks_device_and_key{
	`$shred -uzn 10 $path_to_user_luks_device`;
	`$shred -uzn 10 $path_to_user_keyfile`;
	 crypt_nuke_cleartext_keyfile();
	 true;
}

sub crypt_unmount_crypt_device{
	if($is_mounted){
		`sudo umount $mount_root/$user_hash`;
		`sudo $cryptsetup -q luksClose $user_hash`;
		return true;
	}else{ return false; }
}

=begin crypt_decrypt_keyfile
	Args:	1. user's passphrase for the AES encrypted keyfile
	Decrypts the user's LUKS container's keyfile into a tmp file(used for mounting the LUKS image)
	Once done, we will nuke the clear-text version
=cut
sub crypt_decrypt_keyfile{
	my ($user_passphrase) = shift;
	if(-e $cleartext_tmp_keyfile_path){
		`$shred -uzn 10 $cleartext_tmp_keyfile_path`;
	}

	unless(-e $path_to_user_keyfile){
		print "No such keyfile";
		return false;
	}
	`$openssl aes-256-cbc -d -salt -pbkdf2 -in $path_to_user_keyfile -out $cleartext_tmp_keyfile_path -pass pass:"$user_passphrase"`;
	true;
}

sub crypt_nuke_cleartext_keyfile{
	if(-e $cleartext_tmp_keyfile_path)
	{ `$shred -uzn 10 $cleartext_tmp_keyfile_path`; }
}

sub _is_defined{
	my ($var_to_check, $error_msg) = @_;
	unless(defined $var_to_check || $var_to_check ne '')
	{ print $error_msg."\n"; exit(2); }
}

sub _generate_keyfile{
	my $key_passphrase = shift;
	unless(-e $path_to_user_keyfile){
		`$dd if=/dev/urandom of=$cleartext_tmp_keyfile_path bs=512 count=1 1>/dev/null 2>&1`;
		`$openssl aes-256-cbc -salt -pbkdf2 -in $cleartext_tmp_keyfile_path -out $path_to_user_keyfile -pass pass:"$key_passphrase"`;
	}else{
		`$shred -uzn 10 $path_to_user_keyfile`;
		_generate_keyfile($key_passphrase);
	}
}

1;
