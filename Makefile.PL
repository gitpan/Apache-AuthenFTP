# $Id: Makefile.PL,v 1.3 2002/10/29 15:13:11 reggers Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME          => 'Apache::AuthenFTP',
	DISTNAME      => 'Apache-AuthenFTP',
	VERSION_FROM  => 'AuthenFTP.pm',

	PREREQ_PM	=> {
		Net::FTP	=> 0
	},

	dist		=> {
		COMPRESS	=> "gzip",
		SUFFIX		=> "gz"
	}
);
