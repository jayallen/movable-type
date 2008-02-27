# Movable Type (r) Open Source (C) 2001-2008 Six Apart, Ltd.
# This program is distributed under the terms of the
# GNU General Public License, version 2.
#
# $Id: AtomServer.pm 1174 2008-01-08 21:02:50Z bchoate $

package MT::App::Atompub::Legacy;
use strict;

use base qw( MT::App::Atompub::Weblog );

use MT::I18N qw( encode_text );
use XML::Atom;  # for LIBXML
use XML::Atom::Feed;
use base qw( MT::AtomServer );
use MT::Blog;
use MT::Permission;

use constant NS_CATEGORY => 'http://sixapart.com/atom/category#';
use constant NS_DC => MT::AtomServer::Weblog->NS_DC();

sub login_failure {
    my $app = shift;
    my $ret = $app->SUPER::login_failure(@_);
    return $ret if !$app->{is_soap};

    my $err = $app->errstr;
    my $code = $app->response_code;

    chomp($err = encode_xml($err));
    if ($code >= 400) {
        $app->response_code(500);
        $app->response_message($err);
    }
    $app->response_content_type('text/xml; charset=' . $app->config->PublishCharset);
    # TODO: does not work in the current requires_login -> login -> failure sequence
    return <<FAULT;
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>$code</faultcode>
      <faultstring>$err</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
FAULT
}

sub handle_request {
    my $app = shift;

    if (my $action = $app->get_header('SOAPAction')) {
        $app->{is_soap} = 1;
        $action =~ s/"//g;
        my ($method) = $action =~ m!/([^/]+)$!;
        $app->request_method($method);
    }

    my $out = $app->SUPER::handle_request(@_);
    return if !defined $out;

    if ($app->{is_soap}) {
        $out =~ s!^(<\?xml.*?\?>)!!;
        $out = <<SOAP;
$1
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>$out</soap:Body>
</soap:Envelope>
SOAP
    }

    return $out;
}

sub show_error {
    my $app = shift;
    return $app->SUPER::show_error(@_) if !$app->{is_soap};

    my($err) = @_;
    chomp($err = encode_xml($err));

    my $code = $app->response_code;
    if ($code >= 400) {
        $app->response_code(500);
        $app->response_message($err);
    }
    return <<FAULT;
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>$code</faultcode>
      <faultstring>$err</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
FAULT
}

sub script { $_[0]->{cfg}->AtomScript . '/weblog' }

sub atom_content_type   { 'application/xml' }
sub atom_x_content_type { 'application/x.atom+xml' }

sub edit_link_rel { 'service.edit' }
sub get_posts_order_field { 'authored_on' }

sub new_feed {
    my $app = shift;
    XML::Atom::Feed->new();
}

sub new_with_entry {
    my $app = shift;
    my ($entry) = @_;
    MT::Atom::Entry->new_with_entry($entry);
}

sub apply_basename {}

sub get_weblogs {
    my $app = shift;
    my $user = $app->{user};
    my $iter = $user->is_superuser
        ? MT::Blog->load_iter()
        : MT::Permission->load_iter({ author_id => $user->id });
    my $feed = $app->new_feed();
    my $base = $app->base . $app->uri;
    while (my $thing = $iter->()) {
        if ($thing->isa('MT::Permission')) {
            next unless $thing->can_create_post;
        }
        my $blog = $thing->isa('MT::Blog') ? $thing
            : MT::Blog->load($thing->blog_id);
        my $uri = $base . '/blog_id=' . $blog->id;
        my $blogname = encode_text($blog->name . ' #' . $blog->id, undef, 'utf-8');
        $feed->add_link({ rel => 'service.post', title => $blogname,
                          href => $uri, type => 'application/x.atom+xml' });
        $feed->add_link({ rel => 'service.feed', title => $blogname,
                          href => $uri, type => 'application/x.atom+xml' });
        $feed->add_link({ rel => 'service.upload', title => $blogname,
                          href => $uri . '/svc=upload',
                          type => 'application/x.atom+xml' });
        $feed->add_link({ rel => 'service.categories', title => $blogname,
                          href => $uri . '/svc=categories',
                          type => 'application/x.atom+xml' });
        $feed->add_link({ rel => 'alternate', title => $blogname,
                          href => $blog->site_url,
                          type => 'text/html' });
    }
    $app->response_code(200);
    $app->response_content_type('application/x.atom+xml');
    $feed->as_xml;
}

sub get_categories {
    my $app = shift;
    my $blog = $app->{blog};
    my $iter = MT::Category->load_iter({ blog_id => $blog->id });
    my $doc;
    if (LIBXML) {
        $doc = XML::LibXML::Document->createDocument('1.0', 'utf-8');
        my $root = $doc->createElementNS(NS_CATEGORY, 'categories');
        $doc->setDocumentElement($root);
    } else {
        $doc = XML::XPath::Node::Element->new('categories');
        my $ns = XML::XPath::Node::Namespace->new('#default' => NS_CATEGORY);
        $doc->appendNamespace($ns);
    }
    while (my $cat = $iter->()) {
        my $catlabel = encode_text($cat->label, undef, 'utf-8');
        if (LIBXML) {
            my $elem = $doc->createElementNS(NS_DC, 'subject');
            $doc->getDocumentElement->appendChild($elem);
            $elem->appendChild(XML::LibXML::Text->new($catlabel));
        } else {
            my $elem = XML::XPath::Node::Element->new('subject');
            my $ns = XML::XPath::Node::Namespace->new('#default' => NS_DC);
            $elem->appendNamespace($ns);
            $doc->appendChild($elem);
            $elem->appendChild(XML::XPath::Node::Text->new($catlabel));
        }
    }
    $app->response_code(200);
    $app->response_content_type('application/x.atom+xml');
    if (LIBXML) {
        $doc->toString(1);
    } else {
        return '<?xml version="1.0" encoding="utf-8"?>' . "\n" . $doc->toString;
    }
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
