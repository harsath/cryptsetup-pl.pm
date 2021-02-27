package cryptsetup_pl;
use Digest::MD5 qw/md5_hex/;

chomp(my $openssl = `which openssl`); _is_defined($openssl, "[ERROR] openssl not found");
chomp(my $cryptsetup = `which cryptsetup`); _is_defined($cryptsetup, "[ERROR] cryptsetup not found");
chomp(my $shred = `which shred`); _is_defined($shred, "[ERROR] shred not found");
chomp(my $dd = `which dd`); _is_defined($dd, "[ERROR] dd not found");
chomp(my $blkid = `which blkid`); _is_defined($blkid, "[ERROR] blkid not found");

=begin crypt_init_args
	Initializes the Hash-Ref with various fields for the other handlers to make use of.
	Must be at the start of any operation over a LUKS device.
=cut
sub crypt_init{
	my $cryptHashRef = shift;	
	$cryptHashRef->{user_hash} = crypt_get_username_hash($cryptHashRef->{user_name});
	$cryptHashRef->{path_to_user_luks_device} = 
		"$cryptHashRef->{crypt_devices_dir}/$cryptHashRef->{user_hash}.bin";
	$cryptHashRef->{path_to_user_keyfile} = 
		"$cryptHashRef->{path_to_keyfile_dir}/$cryptHashRef->{user_hash}.key";
	$cryptHashRef->{cleartext_tmp_keyfile_path} = "/tmp/$cryptHashRef->{user_hash}.key";
	1;
}

=begin crypt_create_luks_device
	Creates a new LUKS device with key-file supplied by the user from HashRef
	The key-file is AES-256-CBC encrypted at the server and unlocked by a user's passphrase
	If already exists, it returns
=cut
sub crypt_create_luks_device{
	my $cryptHashRef = shift;
	if(-e $cryptHashRef->{path_to_user_luks_device})
	{ return 0; }
	`$dd if=/dev/zero of=$cryptHashRef->{path_to_user_luks_device} bs=1M \\
		count=$cryptHashRef->{luks_container_size} 1>/dev/null 2>&1`;
	_generate_keyfile($cryptHashRef);
	`sudo $cryptsetup -q luksFormat $cryptHashRef->{path_to_user_luks_device} \\
		$cryptHashRef->{cleartext_tmp_keyfile_path}`;
	crypt_nuke_cleartext_keyfile();
	1;
}

=begin crypt_mount_crypt_device
	Mount a block file of type LUKS device from the Luks-Device-Root given in HashRef
	If not found, it returns false(0)
=cut
sub crypt_mount_luks_device{
	my $cryptHashRef = shift;
	if(!(-e $cryptHashRef->{path_to_user_luks_device}) && !(-e $cryptHashRef->{path_to_user_keyfile})
		&& `file $cryptHashRef->{path_to_user_luks_device} | awk '{print \$2}'` ne "LUKS")
	{ return 0; }

	crypt_decrypt_keyfile($cryptHashRef);
	unless($cryptHashRef->{mounting_first_time}){
		`sudo $cryptsetup -q luksOpen $cryptHashRef->{path_to_user_luks_device} \\
			$cryptHashRef->{user_hash} --key-file "$cryptHashRef->{cleartext_tmp_keyfile_path}"`;
	}else{
		`sudo $cryptsetup -q luksOpen $cryptHashRef->{path_to_user_luks_device} \\
			$cryptHashRef->{user_hash} --key-file $cryptHashRef->{cleartext_tmp_keyfile_path}`;
		`sudo mkfs.ext4 /dev/mapper/$cryptHashRef->{user_hash} 1>/dev/null 2>&1`;
	}
	crypt_nuke_cleartext_keyfile();

	my $user_mapper_mount_path = "$cryptHashRef->{mount_root}/$cryptHashRef->{user_hash}";
	unless(-d $user_mapper_mount_path)
	{ `mkdir -p $user_mapper_mount_path`; }
	`sudo mount /dev/mapper/$cryptHashRef->{user_hash} $user_mapper_mount_path`;
	$cryptHashRef->{is_mounted} = 1;
	unless(_is_defined($ENV{USER}), "[ERROR] \$ENV{USER} not found/undefined")
	{ return 0; }
	`sudo chown -R $ENV{USER} $user_mapper_mount_path`;
	1;
}

=begin crypt_get_uuid_device
	Returns the UUID if the LUKS block device if it is mounted under device mapper
=cut
sub crypt_get_uuid_device{
	my $cryptHashRef = shift;
	if($cryptHashRef->{is_mounted})
	{ return `$blkid /dev/mapper/$cryptHashRef->{user_hash} | awk '{print \$2}'`; }
	return "";
}

=begin crypt_get_username_hash
	Returns the MD5-digest of the given user name's MD5-digest
	(Internally we use MD5-digests to keep track of a user's session)
=cut
sub crypt_get_username_hash{
	md5_hex($_);
}

=begin crypt_nuke_luks_device_and_key
	Used only when if we need to nuke a user's LUKS device + encrypted keyfile.
=cut
sub crypt_nuke_luks_device_and_key{
	my $cryptHashRef = shift;
	`$shred -uzn 10 $cryptHashRef->{path_to_user_luks_device}`;
	`$shred -uzn 10 $cryptHashRef->{path_to_user_keyfile}`;
	 crypt_nuke_cleartext_keyfile();
	 1;
}

=begin crypt_unmount_crypt_device
	Unmounts the mapper special file from the mount root and the LUKS device
=cut
sub crypt_unmount_crypt_device{
	my $cryptHashRef = shift;
	if($cryptHashRef->{is_mounted}){
		`sudo umount $cryptHashRef->{mount_root}/$cryptHashRef->{user_hash}`;
		`sudo $cryptsetup -q luksClose $cryptHashRef->{user_hash}`;
		return 1;
	}else{ return 0; }
}

=begin crypt_decrypt_keyfile
	Decrypts the user's LUKS container's keyfile into a tmp file(used for mounting the LUKS image)
	Once done, we will nuke the clear-text version
=cut
sub crypt_decrypt_keyfile{
	my $cryptHashRef = shift;
	if(-e $cryptHashRef->{cleartext_tmp_keyfile_path}){
		`$shred -uzn 10 $cryptHashRef->{cleartext_tmp_keyfile_path}`;
	}

	unless(-e $cryptHashRef->{path_to_user_keyfile}){
		print "No such keyfile";
		return 0;
	}
	`$openssl aes-256-cbc -d -salt -pbkdf2 -in $cryptHashRef->{path_to_user_keyfile} \\
		-out $cryptHashRef->{cleartext_tmp_keyfile_path} -pass pass:"$cryptHashRef->{user_passphrase}"`;
	1;
}

=begin crypt_nuke_cleartext_keyfile
	"Nukes" the clear text version of the keyfile in the temp dir.
	This is usually called in places where we decrypt the keyfile for mounting/other purpose.
=cut
sub crypt_nuke_cleartext_keyfile{
	my $cryptHashRef = shift;
	if(-e $cryptHashRef->{cleartext_tmp_keyfile_path})
	{ `$shred -uzn 10 $cryptHashRef->{cleartext_tmp_keyfile_path}`; }
}

sub _is_defined{
	my ($var_to_check, $error_msg) = @_;
	unless(defined $var_to_check || $var_to_check ne '')
	{ print $error_msg."\n"; exit(2); }
}

=begin _generate_keyfile
	Encrypt the key-file to a LUKS device with Salted AES-256-CBC PBKDF2 SHA512-digest encryption scheme.
=cut
sub _generate_keyfile{
	my $cryptHashRef = shift;
	unless(-e $cryptHashRef->{path_to_user_keyfile}){
		`$dd if=/dev/urandom of=$cryptHashRef->{cleartext_tmp_keyfile_path} bs=512 count=1 1>/dev/null 2>&1`;
		`$openssl aes-256-cbc -salt -pbkdf2 -in $cryptHashRef->{cleartext_tmp_keyfile_path} \\
			-out $cryptHashRef->{path_to_user_keyfile} -pass pass:"$cryptHashRef->{user_passphrase}"`;
	}else{
		`$shred -uzn 10 $cryptHashRef->{path_to_user_keyfile}`;
		_generate_keyfile($cryptHashRef->{key_passphrase});
	}
}

1;
