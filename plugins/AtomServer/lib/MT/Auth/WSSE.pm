# Movable Type (r) Open Source (C) 2001-2008 Six Apart, Ltd.
# This program is distributed under the terms of the
# GNU General Public License, version 2.
#
# $Id: AtomServer.pm 1174 2008-01-08 21:02:50Z bchoate $

package MT::Auth::WSSE;
use strict;

use MT::I18N qw( encode_text );
use XML::Atom;
use XML::Atom::Util qw( first textValue );
use base qw( MT::Auth::MT );
use MIME::Base64 ();
use Digest::SHA1 ();
use MT::Util qw( encode_xml iso2ts ts2epoch );
use MT::Author;

use constant NS_WSSE => 'http://schemas.xmlsoap.org/ws/2002/07/secext';
use constant NS_WSU  => 'http://schemas.xmlsoap.org/ws/2002/07/utility';

sub auth_header {
    my $auth = shift;
    return 'WSSE profile="UsernameToken"';
}

sub fetch_credentials {
    my $auth = shift;
    my ($param) = @_;
    my $app = $param->{app} or return $auth->error('App is required');
    my %cred;
    if ($app->{is_soap} && $app->can('xml_body')) {
        my $xml = $app->xml_body;
        my $token = first($xml, NS_WSSE, 'UsernameToken')
            or return $auth->error('Unsupported WSSE authentication profile');
        $cred{$_} = textValue($token, NS_WSSE, $_)
            for qw( Username Password Nonce );
        $cred{Created} = textValue($token, NS_WSU, 'Created');
        $cred{PasswordDigest} = delete $cred{Password};
    } else {
        my $req = $app->get_header('X-WSSE') or return;
        $req =~ s/^WSSE //;
        my ($profile);
        ($profile, $req) = $req =~ /(\S+),?\s+(.*)/;
        return $auth->error("Unsupported WSSE authentication profile") 
            if $profile !~ /\bUsernameToken\b/i;
        for my $i (split /,\s*/, $req) {
            my($k, $v) = split /=/, $i, 2;
            $v =~ s/^"//;
            $v =~ s/"$//;
            $cred{$k} = $v;
        }
    }
    for my $field (qw( Username PasswordDigest Nonce Created )) {
        return $auth->error('UsernameToken WSSE requires ' . $field)
            unless $cred{$field};
    }
    return { %$param, %cred };
}

sub validate_credentials {
    my $auth = shift;
    my ($cred) = @_;
    my $app = $cred->{app};

    for my $field (qw( Username PasswordDigest Nonce Created )) {
        return $app->error('UsernameToken WSSE requires ' . $field)
            unless $cred->{$field};
    }

    require MT::Session;
    my $nonce_record = MT::Session->load($cred->{Nonce});
    
    return $app->error("Nonce already used")
        if ($nonce_record && $nonce_record->id eq $cred->{Nonce});
    $nonce_record = new MT::Session();
    $nonce_record->set_values({
        id => $cred->{Nonce},
        start => time,
        kind => 'AN'
    });
    $nonce_record->save();

    my $enc = $app->config->PublishCharset;
    my $username = encode_text($cred->{Username},undef,$enc);
    my $user = MT::Author->load({ name => $username, type => 1 })
        or return $app->error('Invalid login');
    return $app->error('Invalid login')
        unless $user->api_password;
    return $app->error('Invalid login')
        unless $user->is_active;
    my $created_on_epoch = ts2epoch(undef, iso2ts(undef, $cred->{Created}));
    if (abs(time - $created_on_epoch) > $app->config('WSSETimeout')) {
        return $app->error('X-WSSE UsernameToken timed out');
    }
    $cred->{Nonce} = MIME::Base64::decode_base64($cred->{Nonce});
    my $expected = Digest::SHA1::sha1_base64(
         $cred->{Nonce} . $cred->{Created} . $user->api_password);
    # Some base64 implementors do it wrong and don't put the =
    # padding on the end. This should protect us against that without
    # creating any holes.
    $expected =~ s/=*$//;
    $cred->{PasswordDigest} =~ s/=*$//;
    #print STDERR "expected $expected and got " . $cred->{PasswordDigest} . "\n";
    return $app->error('X-WSSE PasswordDigest is incorrect')
        unless $expected eq $cred->{PasswordDigest};

    $app->user($user);
    return MT::Auth->NEW_LOGIN();  # always new
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
