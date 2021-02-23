package cryptsetup_pl;
use Digest::MD5 qw/md5_hex/;

sub crypt_init{
	my ($)
}

sub crypt_create_luks_device{}

sub crypt_mount_crypt_device{
	my ($device_name, $device_path) = @_;
}

sub crypt_get_uuid_device{}

sub crypt_create_block_device{}

sub crypt_get_username_hash{}

sub crypt_check_already_mount{}

sub crypt_nuke_luks_device{}

sub crypt_unmount_crypt_device{}

sub crypt_decrypt_keyfile{}

1;
