#!/usr/bin/perl
use warnings;
use strict;

qx/sudo apt update -y/;

my @install_apt_deps = (
	"cryptsetup", "coreutils"
);

my @install_perl_module_deps = (
	"Digest::MD5",
	"Crypt::PBKDF2"
);

for(@install_apt_deps){ system("sudo apt install $_ -y"); }
for(@install_perl_module_deps){ system("cpan install $_"); }
