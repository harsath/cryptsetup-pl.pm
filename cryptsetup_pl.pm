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
my $key_file_out_fullpath;
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
	$path_to_user_keyfile = "$path_to_keyfile_dir/$user_hash";
	$key_file_out_fullpath = "/tmp/$user_hash.key";
	$key_file_in_fullpath = "$path_to_keyfile_dir/$user_hash.key";
	true;
}

=begin crypt_create_luks_device
	Args:	1. passphrase for the keyfile which will be encrypted by AES-256-CBC and stored on server
=cut
sub crypt_create_luks_device{
	my $keyfile_passphrase = @_;
	if(-e $path_to_user_luks_device)
	{ return false; }
	`dd if=/dev/zero of=$path_to_user_luks_device bs=1M count=$luks_container_size`;
	_generate_keyfile($keyfile_passphrase);
	`sudo $cryptsetup -q luksFormat $path_to_user_luks_device $path_to_user_keyfile`;
	true;
}

=begin crypt_mount_crypt_device
	Args:	1. Is the LUKS device/image mounting for first time? Because If so, we need to
	 	   create a File-System on the fresh LUKS block device.
=cut
sub crypt_mount_crypt_device{
	my $mounting_first_time = @_;
	unless(-e $path_to_user_luks_device && -e $path_to_user_keyfile && 
	       `file $path_to_user_luks_device | awk '{print \$2}'` eq "LUKS")
	{ return false; }

	unless($mounting_first_time){
		`sudo $cryptsetup -q luksOpen $path_to_user_luks_device $user_hash --key-file $path_to_user_keyfile`;
	}else{
		`sudo $cryptsetup -q luksOpen $path_to_user_luks_device $user_hash --key-file $path_to_user_keyfile`;
		`sudo mkfs.ext4 /dev/mapper/$user_hash`;
	}

	my $user_mapper_mount_path = "$mount_root/$user_hash";
	unless(-d $user_mapper_mount_path)
	{ `mkdir -p $user_mapper_mount_path`; }
	`sudo mount /dev/mapper/$user_hash $user_mapper_mount_path $path_to_`; $is_mounted = true;
	unless(_is_defined($ENV{USER}), "[ERROR] \$ENV{USER} not found/undefined"){ return false; }
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
	$key_file_out_fullpath;
}

sub crypt_get_keyfile_in_path{
	$key_file_in_fullpath;
}

sub crypt_get_user_luks_device_path{
	$path_to_user_luks_device;
}

sub crypt_get_user_dir_mount_path{
	"$mount_root/$user_hash";
}

sub crypt_nuke_luks_device_and_key{
	`$shred -uzn 10 $path_to_user_luks_device`;
	`$shred -uzn 10 $key_file_in_fullpath`;
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
	my ($user_passphrase) = @_;
	my $iter = 100000;
	if(-e $key_file_out_fullpath){
		`$shred -uzn 10 $key_file_out_fullpath`;
		`touch $key_file_out_fullpath && chmod 700 $key_file_out_fullpath`;
	}

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
	unless(defined $var_to_check || $var_to_check ne '')
	{ print $error_msg."\n"; exit(2); }
}

sub _generate_keyfile{
	my $key_passphrase = @_;
	unless(-e $key_file_in_fullpath){
		`touch $key_file_out_fullpath`;
		print "name: $key_file_out_fullpath\n";
		`$dd if=/dev/urandom of=$key_file_out_fullpath bs=512 count=1 && chmod 700 $key_file_out_fullpath`;
		`$openssl enc -e -aes-256-cbc -md sha512 -pbkdf2 -iter 100000 -salt -in $key_file_out_fullpath -out $key_file_in_fullpath -pass pass:$key_passphrase`;
		 crypt_nuke_cleartext_keyfile();
	}else{
		`$shred -uzn 10 $key_file_in_fullpath`;
		_generate_keyfile($key_passphrase);
	}
}

1;
