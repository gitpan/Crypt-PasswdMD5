use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

# $Id: Makefile.PL,v 1.2 2004/02/17 11:20:45 lem Exp $

print <<EOF;
======================================================================
			       WARNING
======================================================================

Due to  the nature of this  Perl package, I strongly  suggest that its
signature be properly verified using GPG.

EOF
    ;

WriteMakefile(
    'NAME'		=> 'Crypt::PasswdMD5',
    'VERSION_FROM'	=> 'PasswdMD5.pm',
    'LIBS'		=> [''],
    'INC'		=> '',
	      ($] >= 5.005 ? 
	       (ABSTRACT_FROM	=> 'PasswdMD5.pm',
		AUTHOR     	=> 'Luis E. Muñoz <luismunoz@cpan.org>') : ()),
);

