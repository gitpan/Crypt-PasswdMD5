#
# Basic testing of the hashing function
#

use Crypt::PasswdMD5;

$phrase1 = "hello world\n";
$stage1 = '$1$1234$BhY1eAOOs7IED4HLA5T5o.';

$|=1;

print "1..3\n";

# Hashing of a simple phrase + salt
if (unix_md5_crypt($phrase1, "1234") eq $stage1) {
	print "ok 1\n";
}
else {
	print "not ok 1\n";
}

# Rehash (check) of the phrase
if (unix_md5_crypt($phrase1, $stage1) eq $stage1) {
	print "ok 2\n";
}
else {
	print "not ok 2\n";
}

# Hasing/rehashing of the empty password
$t = unix_md5_crypt('', $$);
if (unix_md5_crypt('', $t) eq $t) {
	print "ok 3\n";
}
else
{	
	print "not ok 3\n";
}





