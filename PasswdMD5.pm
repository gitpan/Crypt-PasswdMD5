#
# Crypt::PasswdMD5: Module to provide an interoperable crypt() 
#	function for modern Unix O/S. This is based on the code for
#
# /usr/src/libcrypt/crypt.c
#
# on a FreeBSD 2.2.5-RELEASE system, which included the following
# notice.
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
# ----------------------------------------------------------------------------
#
# 19980710 lem@cantv.net: Initial release
#
################

package Crypt::PasswdMD5;
$VERSION='0.1';
require 5.000;
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(unix_md5_crypt);

=head1 NAME

unix_md5_crypt - Provides interoperable MD5-based crypt() function

=head1 SYNOPSIS

	use Crypt::PasswdMD5;

	$cryptedpassword = unix_md5_crypt($password, $salt);

=head1 DESCRIPTION

the unix_md5_crypt() provides a crypt()-compatible interface to the
rather new MD5-based crypt() function found in modern operating systems.
It's based on the implementation found on FreeBSD 2.2.[56]-RELEASE and
contains the following license in it:

 "THE BEER-WARE LICENSE" (Revision 42):
 <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 can do whatever you want with this stuff. If we meet some day, and you think
 this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

=cut

$Magic = '$1$';			# Magic string
$itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

use MD5;

sub to64 {
    my ($v, $n) = @_;
    my $ret = '';
    while (--$n >= 0) {
	$ret .= substr($itoa64, $v & 0x3f, 1);
	$v >>= 6;
    }
    $ret;
}

sub unix_md5_crypt {
    my($pw, $salt) = @_;
    my $passwd;

    $salt =~ s/^\Q$Magic//;	# Take care of the magic string if
				# if present.

    $salt =~ s/^(.*)\$.*$/$1/;	# Salt can have up to 8 chars...
    $salt = substr($salt, 0, 8);

    $ctx = new MD5;		# Here we start the calculation
    $ctx->add($pw);		# Original password...
    $ctx->add($Magic);		# ...our magic string...
    $ctx->add($salt);		# ...the salt...

    my ($final) = new MD5;
    $final->add($pw);
    $final->add($salt);
    $final->add($pw);
    $final = $final->digest;

    for ($pl = length($pw); $pl > 0; $pl -= 16) {
	$ctx->add(substr($final, 0, $pl > 16 ? 16 : $pl));
    }

				# Now the 'weird' xform

    for ($i = length($pw); $i; $i >>= 1) {
	if ($i & 1) { $ctx->add(pack("C", 0)); }
				# This comes from the original version,
				# where a memset() is done to $final
				# before this loop.
	else { $ctx->add(substr($pw, 0, 1)); }
    }

    $final = $ctx->digest;
				# The following is supposed to make
				# things run slower. In perl, perhaps
				# it'll be *really* slow!

    for ($i = 0; $i < 1000; $i++) {
	$ctx1 = new MD5;
	if ($i & 1) { $ctx1->add($pw); }
	else { $ctx1->add(substr($final, 0, 16)); }
	if ($i % 3) { $ctx1->add($salt); }
	if ($i % 7) { $ctx1->add($pw); }
	if ($i & 1) { $ctx1->add(substr($final, 0, 16)); }
	else { $ctx1->add($pw); }
	$final = $ctx1->digest;
    }
    
				# Final xform

    $passwd = '';
    $passwd .= to64(int(unpack("C", (substr($final, 0, 1))) << 16)
		    | int(unpack("C", (substr($final, 6, 1))) << 8)
		    | int(unpack("C", (substr($final, 12, 1)))), 4);
    $passwd .= to64(int(unpack("C", (substr($final, 1, 1))) << 16)
		    | int(unpack("C", (substr($final, 7, 1))) << 8)
		    | int(unpack("C", (substr($final, 13, 1)))), 4);
    $passwd .= to64(int(unpack("C", (substr($final, 2, 1))) << 16)
		    | int(unpack("C", (substr($final, 8, 1))) << 8)
		    | int(unpack("C", (substr($final, 14, 1)))), 4);
    $passwd .= to64(int(unpack("C", (substr($final, 3, 1))) << 16)
		    | int(unpack("C", (substr($final, 9, 1))) << 8)
		    | int(unpack("C", (substr($final, 15, 1)))), 4);
    $passwd .= to64(int(unpack("C", (substr($final, 4, 1))) << 16)
		    | int(unpack("C", (substr($final, 10, 1))) << 8)
		    | int(unpack("C", (substr($final, 5, 1)))), 4);
    $passwd .= to64(int(unpack("C", substr($final, 11, 1))), 2);

    $final = '';
    $Magic . $salt . '$' . $passwd;
}

1;



