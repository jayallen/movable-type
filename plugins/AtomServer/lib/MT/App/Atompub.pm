# Movable Type (r) Open Source (C) 2001-2008 Six Apart, Ltd.
# This program is distributed under the terms of the
# GNU General Public License, version 2.
#
# $Id: AtomServer.pm 1174 2008-01-08 21:02:50Z bchoate $

package MT::App::Atompub;
use strict;

use MT::I18N qw( encode_text );
use XML::Atom;
use XML::Atom::Util qw( first textValue );
use base qw( MT::App::API );
use MIME::Base64 ();
use Digest::SHA1 ();
use MT::Atom;
use MT::Util qw( encode_xml );
use MT::Author;

sub init {
    my $app = shift;
    $app->SUPER::init(@_);
    $app->{requires_login} = 1;
    $app;
}

sub handle_request {
    # Don't dispatch to handle_METHOD methods.
    1;
}

sub error {
    my $app = shift;
    my($code, $msg) = @_;
    return unless ref($app);
    if ($code && $msg) {
        $app->response_code($code);
        $app->response_message($msg);
    }
    elsif ($code) {
        return $app->SUPER::error($code);
    }
    return undef;
}

sub show_error {
    my $app = shift;
    my($err) = @_;
    chomp($err = encode_xml($err));
    $app->response_content_type('text/xml');
    return <<ERR;
<error>$err</error>
ERR
}

sub xml_body {
    my $app = shift;
    unless (exists $app->{xml_body}) {
        if (LIBXML) {
            my $parser = XML::LibXML->new;
            $app->{xml_body} = $parser->parse_string($app->request_content);
        } else {
            my $xp = XML::XPath->new(xml => $app->request_content);
            $app->{xml_body} = ($xp->find('/')->get_nodelist)[0];
        }
    }
    $app->{xml_body};
}

sub atom_body {
    my $app = shift;
    return MT::Atom::Entry->new(Stream => \$app->request_content)
        or $app->error(500, MT::Atom::Entry->errstr);
}

# $target_zone is expected to be a number of hours from GMT
sub iso2ts {
    my $app = shift;
    my($ts, $target_zone) = @_;
    return unless $ts =~ /^(\d{4})(?:-?(\d{2})(?:-?(\d\d?)(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-]\d{2}:\d{2}))?)?)?)?/;
    my($y, $mo, $d, $h, $m, $s, $zone) =
        ($1, $2 || 1, $3 || 1, $4 || 0, $5 || 0, $6 || 0, $7);
    if ($zone) {
        my ($zh, $zm) = $zone =~ /([+-]\d\d):(\d\d)/;
        use Time::Local qw( timegm );
        my $ts = timegm( $s, $m, $h, $d, $mo - 1, $y - 1900 );
        if ($zone ne 'Z') {
            require MT::DateTime;
            my $tz_secs = MT::DateTime->tz_offset_as_seconds($zone);
            $ts -= $tz_secs;
        }
        if ($target_zone) {
            my $tz_secs = (3600 * int($target_zone) + 
                           60 * abs($target_zone - int($target_zone)));
            $ts += $tz_secs;
        }
        ($s, $m, $h, $d, $mo, $y) = gmtime( $ts );
        $y += 1900; $mo++;
    }
    sprintf("%04d%02d%02d%02d%02d%02d", $y, $mo, $d, $h, $m, $s);
}

sub iso2epoch {
    my $app = shift;
    my($ts) = @_;
    return unless $ts =~ /^(\d{4})(?:-?(\d{2})(?:-?(\d\d?)(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-]\d{2}:\d{2}))?)?)?)?/;
    my($y, $mo, $d, $h, $m, $s, $zone) =
        ($1, $2 || 1, $3 || 1, $4 || 0, $5 || 0, $6 || 0, $7);

    use Time::Local;
    my $dt = timegm($s, $m, $h, $d, $mo-1, $y);
    if ($zone && $zone ne 'Z') {
        require MT::DateTime;
        my $tz_secs = MT::DateTime->tz_offset_as_seconds($zone);
        $dt -= $tz_secs;
    }
    $dt;
}

1;
__END__

=head1 NAME

MT::AtomServer

=head1 SYNOPSIS

An Atom Publishing API interface for communicating with Movable Type.

=head1 METHODS

=head2 $app->xml_body()

Takes the content posted to the server and parses it into an XML document.
Uses either XML::LibXML or XML::XPath depending on which is available.

=head2 $app->iso2epoch($iso_ts)

Converts C<$iso_ts> in the format of an ISO timestamp into a unix timestamp
(seconds since the epoch).

=head2 $app->init

Initializes the application.

=head2 $app->get_auth_info

Processes the request for WSSE authentication and returns a hash containing:

=over 4

=item * Username

=item * PasswordDigest

=item * Nonce

=item * Created

=back

=head2 $app->handle_request

The implementation of this in I<MT::AtomServer::Weblog> passes the request
to the proper method.

=head2 $app->handle

Wrapper method that determines the proper AtomServer package to pass the
request to.

=head2 $app->iso2ts($iso_ts, $target_zone)

Converts C<$iso_ts> in the format of an ISO timestamp into a MT-compatible
timestamp (YYYYMMDDHHMMSS) for the specified timezone C<$target_zone>.

=head2 $app->atom_body

Processes the request as Atom content and returns an XML::Atom object.

=head2 $app->error($code, $message)

Sends the HTTP headers necessary to relay an error.

=head2 $app->authenticate()

Checks the WSSE authentication with the local MT user database and
confirms the user is authorized to access the resources required by
the request.

=head2 $app->show_error($message)

Returns an XML wrapper for the error response.

=head2 $app->auth_failure($code, $message)

Handles the response in the event of an authentication failure.

=head1 CALLBACKS

=over 4

=item api_pre_save.entry

    callback($eh, $app, $entry, $original_entry)

Called before saving a new or existing entry. If saving a new entry, the
$original_entry will have an unassigned 'id'. This callback is executed
as a filter, so your handler must return 1 to allow the entry to be saved.

=item api_post_save.entry

    callback($eh, $app, $entry, $original_entry)

Called after saving a new or existing entry. If saving a new entry, the
$original_entry will have an unassigned 'id'.

=back

=cut
