package Apache::AuthenFTP;

$Apache::AuthenFTP::VERSION = '0.01';

# $Id: AuthenFTP.pm,v 1.14 2002/10/23 19:34:18 reggers Exp $

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use Net::FTP;

use strict;

sub handler {
    my $r = shift;

    # Continue only if the first request.

    return OK unless $r->is_initial_req;

    # Grab the password, or return if HTTP_UNAUTHORIZED

    my ($res, $pass) = $r->get_basic_auth_pw;
    return $res if $res;

    # Get the user name, but reject anonymous ftp

    my $user = $r->connection->user;
    if (($user eq '') ||
	(lc($user) eq "ftp") ||
        (lc($user) eq "anonymous")) {
	    $r->log_reason("Apache::AuthenFTP (anon) $user", $r->uri);
	    $r->note_basic_auth_failure;
	    return AUTH_REQUIRED;
	}

    # get host/port from Apache configuration
    # defaults are ftp service on this machine

    my $host = $r->dir_config("Auth_FTP_host") || "localhost";
    my $port = $r->dir_config("Auth_FTP_port") || "ftp";

    # connect to FTP server and authenticate

    my $ftp= Net::FTP->new($host, (Port => $port));
    if (!defined($ftp)) {
	$r->log_reason("Apache::AuthenFTP (conn) $port://$host", $r->uri);
	return SERVER_ERROR;
    }

    my $stat= $ftp->login($user,$pass); $ftp->quit();

    # Check login status and return accordingly.

    if (!defined($stat) || !$stat) {
        $r->log_reason("Apache::AuthenFTP (auth) FAIL", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    return OK;
}

1;

__END__

=head1 NAME

Apache::AuthenFTP - Authentication via an FTP server

=head1 SYNOPSIS

 # Configuration in httpd.conf

 PerlModule Apache::AuthenFTP

 # Authentication in .htaccess

 AuthName FTP User Authentication
 AuthType Basic

 # authenticate via FTP
 PerlAuthenHandler Apache::AuthenFTP

 # PerlSetVar Auth_FTP_host localhost
 PerlSetVar Auth_FTP_host do.ma.in
 # PerlSetVar Auth_FTP_port 21
 PerlSetVar Auth_FTP_port 2003

 require user fred

The AuthType is limited to Basic.

=head1 DESCRIPTION

This module allows authentication against servers that implement
the FTP authentication protocol (simple gateways that don't implement
all of the FTP protocol will suffice).

AuthenFTP relies on the Net::FTP module to do the real work.

=head1 LIST OF TOKENS

=over 4

=item *
Auth_FTP_host

The FTP server host: either its name or its dotted quad IP number.
This parameter defaults to "localhost" -- the loopback interface to
the same system.

=item *
Auth_FTP_port

The port on which the FTP server is listening: either its service
name or its actual port number. This parameter defaults to "ftp"
which is the official service name for FTP servers.

=back

=head1 BEWARE

The FTP protocol is very simple -- passwords are passed in the clear and
may be snooped on insecure networks. Using the FTP service on the localhost
is secure as there is no network data to be snooped.

An anonymous FTP server will let authenticate users "anonymous" and
"ftp" with virtually any password -- this module will not attempt to
authenticate either of those users. Many FTP servers restrict user
access based on the user's login shell (see /etc/shells) and/or
exclusion lists (see /etc/ftpusers).

=head1 AUTHORS

This module B<Apache::AuthenFTP> by Reg Quinton
E<lt>reggers@ist.uwaterloo.caE<gt> using strategy of AuthenIMAP by Malcolm
Beattie.

=head1 COPYRIGHT

The Apache::AuthenFTP module is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
