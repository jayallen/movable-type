# Movable Type (r) Open Source (C) 2001-2008 Six Apart, Ltd.
# This program is distributed under the terms of the
# GNU General Public License, version 2.
#
# $Id: AtomServer.pm 1174 2008-01-08 21:02:50Z bchoate $

package MT::App::Atompub::Weblog;
use strict;

use MT::I18N qw( encode_text );
use XML::Atom;
use XML::Atom::Feed;
use base qw( MT::App::Atompub );
use MT::Blog;
use MT::Entry;
use MT::Util qw( encode_xml );
use MT::Permission;
use File::Spec;
use File::Basename;

use constant NS_APP => 'http://www.w3.org/2007/app';
use constant NS_DC => 'http://purl.org/dc/elements/1.1/';
use constant NS_TYPEPAD => 'http://sixapart.com/atom/typepad#';

sub script { $_[0]->{cfg}->AtomScript . '/1.0' }

sub atom_content_type   { 'application/atom+xml' }
sub atom_x_content_type { 'application/atom+xml' }

sub edit_link_rel { 'edit' }
sub get_posts_order_field { 'modified_on' }

sub new_feed {
    my $app = shift;
    XML::Atom::Feed->new( Version => 1.0 );
}

sub new_with_entry {
    my $app = shift;
    my ($entry) = @_;
    my $atom = MT::Atom::Entry->new_with_entry( $entry, Version => 1.0 );

    my $mo = MT::Atom::Entry::_create_issued($entry->modified_on, $entry->blog);
    $atom->set(NS_APP(), 'edited', $mo);

    $atom;
}

sub apply_basename {
    my $app = shift;
    my ($entry, $atom) = @_;

    if (my $basename = $app->get_header('Slug')) {
        my $entry_class = ref $entry;
        my $basename_uses = $entry_class->count({
            blog_id  => $entry->blog_id,
            basename => $basename,
            ($entry->id ? ( id => { op => '!=', value => $entry->id } ) : ()),
        });
        if ($basename_uses) {
            $basename = MT::Util::make_unique_basename($entry);
        }

        $entry->basename($basename);
    }

    $entry;
}

sub handle_request {
    my $app = shift;

    #TODO: ugly.  need to come up with a cleaner way
    unless ( $app->check_perms ) {
        bless $app, 'MT::App::API';
        return $app->login_failure(403, 'Forbidden');
    }

    if (my $svc = $app->{param}{svc}) {
        if ($svc eq 'upload') {
            return $app->handle_upload;
        } elsif ($svc eq 'categories') {
            return $app->get_categories;
        }
    }
    my $method = $app->request_method;
    if ($method eq 'POST') {
        return $app->new_post;
    } elsif ($method eq 'PUT') {
        return $app->edit_post;
    } elsif ($method eq 'DELETE') {
        return $app->delete_post;
    } elsif ($method eq 'GET') {
        if ($app->{param}{entry_id}) {
            return $app->get_post;
        } elsif ($app->{param}{blog_id}) {
            return $app->get_posts;
        } else {
            return $app->get_weblogs;
        }
    }
}

sub check_perms {
    my $app = shift;

    if (my $blog_id = $app->{param}{blog_id}) {
        $app->{blog} = MT::Blog->load($blog_id)
            or return $app->error("Invalid blog ID '$blog_id'");
        if ($app->user->is_superuser()) {
            $app->{perms} = new MT::Permission;
            $app->{perms}->blog_id($blog_id);
            $app->{perms}->author_id($app->user->id);
            $app->{perms}->can_administer_blog(1);
            return 1;
        }
        my $perms = $app->{perms} = MT::Permission->load({
                    author_id => $app->user->id,
                    blog_id => $app->{blog}->id });
        return $app->error("Permission denied.") unless $perms && $perms->can_create_post;
    }
    1;
}

sub publish {
    my $app = shift;
    my($entry, $no_ping) = @_;
    my $blog = MT::Blog->load($entry->blog_id);
    $app->rebuild_entry( Entry => $entry, Blog => $blog,
                         BuildDependencies => 1 ) or return;
    unless ($no_ping) {
        $app->ping_and_save( Entry => $entry, Blog => $blog )
            or return;
    }
    1;
}

sub get_weblogs {
    my $app = shift;
    my $user = $app->user or return $app->auth_failure(403, 'No authentication');
    my $iter = $user->is_superuser
        ? MT::Blog->load_iter()
        : MT::Permission->load_iter({ author_id => $user->id });
    my $base = $app->base . $app->uri;

    # TODO: libxml support? XPath should always be available...
    require XML::XPath;
    require XML::XPath::Node::Element;
    require XML::XPath::Node::Namespace;
    require XML::XPath::Node::Text;

    my $doc = XML::XPath::Node::Element->new('service');
    my $app_ns = XML::XPath::Node::Namespace->new('#default' => NS_APP());
    $doc->appendNamespace($app_ns);
    my $atom_ns = XML::XPath::Node::Namespace->new('atom' => 'http://www.w3.org/2005/Atom');
    $doc->appendNamespace($atom_ns);

    while (my $thing = $iter->()) {
        # TODO: provide media collection if author can upload to this blog.
        if ($thing->isa('MT::Permission')) {
            next if !$thing->can_create_post;
        }

        my $blog = $thing->isa('MT::Blog') ? $thing
            : MT::Blog->load($thing->blog_id);
        my $uri = $base . '/blog_id=' . $blog->id;

        my $workspace = XML::XPath::Node::Element->new('workspace');
        $doc->appendChild($workspace);

        my $title = XML::XPath::Node::Element->new('atom:title', 'atom');
        $title->appendChild(XML::XPath::Node::Text->new($blog->name));
        $workspace->appendChild($title);

        my $entries = XML::XPath::Node::Element->new('collection');
        $entries->appendAttribute(XML::XPath::Node::Attribute->new('href', $uri));
        $workspace->appendChild($entries);

        my $e_title = XML::XPath::Node::Element->new('atom:title', 'atom');
        $e_title->appendChild(XML::XPath::Node::Text->new(MT->translate('Entries')));
        $entries->appendChild($e_title);

        my $cats = XML::XPath::Node::Element->new('categories');
        $cats->appendAttribute(XML::XPath::Node::Attribute->new('href', $uri . '?svc=categories'));
        $entries->appendChild($cats);
    }
    $app->response_code(200);
    $app->response_content_type('application/atomsvc+xml');
    '<?xml version="1.0" encoding="utf-8"?>' . "\n" .                                                          
        $doc->toString;
}

sub get_categories {
    my $app = shift;
    my $blog = $app->{blog};

    # TODO: libxml support? XPath should always be available...
    require XML::XPath;
    require XML::XPath::Node::Element;
    require XML::XPath::Node::Namespace;
    require XML::XPath::Node::Text;

    my $doc = XML::XPath::Node::Element->new('categories');
    my $app_ns = XML::XPath::Node::Namespace->new('#default' => NS_APP());
    $doc->appendNamespace($app_ns);
    my $atom_ns = XML::XPath::Node::Namespace->new('atom' => 'http://www.w3.org/2005/Atom');
    $doc->appendNamespace($atom_ns);
    $doc->appendAttribute(XML::XPath::Node::Attribute->new('fixed', 'yes'));

    my $iter = MT::Category->load_iter({ blog_id => $blog->id });
    while (my $cat = $iter->()) {
        my $cat_node = XML::XPath::Node::Element->new('atom:category', 'atom');
        $cat_node->appendAttribute(XML::XPath::Node::Attribute->new('term', $cat->label));
        $doc->appendChild($cat_node);
    }

    $app->response_code(200);
    $app->response_content_type('application/atomcat+xml');
    '<?xml version="1.0" encoding="utf-8"?>' . "\n" .                                                          
        $doc->toString;
}

sub new_post {
    my $app = shift;
    my $atom = $app->atom_body or return $app->error(500, "No body!");
    my $blog = $app->{blog};
    my $user = $app->user;
    my $perms = $app->{perms};
    my $enc = $app->config('PublishCharset');
    ## Check for category in dc:subject. We will save it later if
    ## it's present, but we want to give an error now if necessary.
    my($cat);
    if (my $label = $atom->get(NS_DC, 'subject')) {
        my $label_enc = encode_text($label,'utf-8',$enc);
        $cat = MT::Category->load({ blog_id => $blog->id, label => $label_enc })
            or return $app->error(400, "Invalid category '$label'");
    }

    my $content = $atom->content;
    my $type = $content->type; 
    my $body = encode_text(MT::I18N::utf8_off($content->body),'utf-8',$enc); 
    my $asset;
    if ($type && $type !~ m!^application/.*xml$!) {
        if ($type !~ m!^text/!) {
            $asset = $app->_upload_to_asset or return;
        }
        elsif ($type && $type eq 'text/plain') {
            ## Check for LifeBlog Note & SMS records.
            my $format = $atom->get(NS_DC, 'format');
            if ($format && ($format eq 'Note' || $format eq 'SMS')) {
                $asset = $app->_upload_to_asset or return;
            }
        }
    }
    if ( $atom->get(NS_TYPEPAD, 'standalone') && $asset ) {
        $app->response_code(201);
        $app->response_content_type('application/atom_xml');
        my $a = MT::Atom::Entry->new_with_asset($asset);
        return $a->as_xml; 
    } 

    my $entry = MT::Entry->new;
    my $orig_entry = $entry->clone;
    $entry->blog_id($blog->id);
    $entry->author_id($user->id);
    $entry->created_by($user->id);
    $entry->status($perms->can_publish_post ? MT::Entry::RELEASE() : MT::Entry::HOLD() );
    $entry->allow_comments($blog->allow_comments_default);
    $entry->allow_pings($blog->allow_pings_default);
    $entry->convert_breaks($blog->convert_paras);
    $entry->title(encode_text($atom->title,'utf-8',$enc));
    $entry->text(encode_text(MT::I18N::utf8_off($atom->content()->body()),'utf-8',$enc));
    $entry->excerpt(encode_text($atom->summary,'utf-8',$enc));
    if (my $iso = $atom->issued) {
        my $pub_ts = MT::Util::iso2ts($blog, $iso);
        my @ts = MT::Util::offset_time_list(time, $blog->id);
        my $ts = sprintf '%04d%02d%02d%02d%02d%02d',
            $ts[5]+1900, $ts[4]+1, @ts[3,2,1,0];
        $entry->authored_on($pub_ts);
        if ($pub_ts > $ts) {
            $entry->status(MT::Entry::FUTURE())
        }
    }
## xxx mt/typepad-specific fields
    $app->apply_basename($entry, $atom);
    $entry->discover_tb_from_entry();

    if (my @link = $atom->link) {
        my $i = 0;
        my $img_html = '';
        my $num_links = scalar @link;
        for my $link (@link) {
            next unless $link->rel eq 'related';
            my($asset_id) = $link->href =~ /asset\-(\d+)$/;
            if ($asset_id) {
                require MT::Asset;
                my $a = MT::Asset->load($asset_id);
                next unless $a;
                my $pkg = MT::Asset->handler_for_file($a->file_name);
                my $asset = bless $a, $pkg;
                $img_html .= $asset->as_html({ include => 1 });
            }
        }
        if ($img_html) {
            $img_html .= qq{<br style="clear: left;" />\n\n};
            $entry->text($img_html . $body);
        }
    }

    MT->run_callbacks('api_pre_save.entry', $app, $entry, $orig_entry)
        or return $app->error(500, MT->translate("PreSave failed [_1]", MT->errstr));

    $entry->save or return $app->error(500, $entry->errstr);

    require MT::Log;
    $app->log({
        message => $app->translate("User '[_1]' (user #[_2]) added [lc,_4] #[_3]", $user->name, $user->id, $entry->id, $entry->class_label),
        level => MT::Log::INFO(),
        class => 'entry',
        category => 'new',
        metadata => $entry->id
    });
    ## Save category, if present.
    if ($cat) {
        my $place = MT::Placement->new;
        $place->is_primary(1);
        $place->entry_id($entry->id);
        $place->blog_id($blog->id);
        $place->category_id($cat->id);
        $place->save or return $app->error(500, $place->errstr);
    }

    MT->run_callbacks('api_post_save.entry', $app, $entry, $orig_entry);

    $app->publish($entry);
    $app->response_code(201);
    $app->response_content_type('application/atom+xml');
    my $edit_uri = $app->base . $app->uri . '/blog_id=' . $entry->blog_id . '/entry_id=' . $entry->id;
    $app->set_header('Location', $edit_uri);
    $atom = $app->new_with_entry($entry);
    $atom->add_link({ rel => $app->edit_link_rel,
                      href => $edit_uri,
                      type => 'application/atom+xml',  # even in Legacy
                      title => $entry->title });
    $atom->as_xml;
}

sub edit_post {
    my $app = shift;
    my $atom = $app->atom_body or return;
    my $blog = $app->{blog};
    my $enc = $app->config('PublishCharset');
    my $entry_id = $app->{param}{entry_id}
        or return $app->error(400, "No entry_id");
    my $entry = MT::Entry->load($entry_id)
        or return $app->error(400, "Invalid entry_id");
    return $app->error(403, "Access denied")
        unless $app->{perms}->can_edit_entry($entry, $app->user);
    my $orig_entry = $entry->clone;
    $entry->title(encode_text($atom->title,'utf-8',$enc));
    $entry->text(encode_text(MT::I18N::utf8_off($atom->content()->body()),'utf-8',$enc));
    $entry->excerpt(encode_text($atom->summary,'utf-8',$enc));
    $entry->modified_by($app->user->id);
    if (my $iso = $atom->issued) {
        my $pub_ts = MT::Util::iso2ts($blog, $iso);
        my @ts = MT::Util::offset_time_list(time, $blog->id);
        my $ts = sprintf '%04d%02d%02d%02d%02d%02d',
            $ts[5]+1900, $ts[4]+1, @ts[3,2,1,0];
        $entry->authored_on($pub_ts);
        if ($pub_ts > $ts) {
            $entry->status(MT::Entry::FUTURE())
        }
    }
## xxx mt/typepad-specific fields
    $app->apply_basename($entry, $atom);
    $entry->discover_tb_from_entry();

    MT->run_callbacks('api_pre_save.entry', $app, $entry, $orig_entry)
        or return $app->error(500, MT->translate("PreSave failed [_1]", MT->errstr));

    $entry->save or return $app->error(500, "Entry not saved");

    require MT::Log;
    $app->log({
        message => $app->translate("User '[_1]' (user #[_2]) edited [lc,_4] #[_3]", $app->user->name, $app->user->id, $entry->id, $entry->class_label),
        level => MT::Log::INFO(),
        class => 'entry',
        category => 'new',
        metadata => $entry->id
    });

    MT->run_callbacks('api_post_save.entry', $app, $entry, $orig_entry);

    if ($entry->status == MT::Entry::RELEASE()) {
        $app->publish($entry) or return $app->error(500, "Entry not published");
    }
    $app->response_code(200);
    $app->response_content_type($app->atom_content_type);
    $atom = $app->new_with_entry($entry);
    $atom->as_xml;
}

sub get_posts {
    my $app = shift;
    my $blog = $app->{blog};
    my %terms = (blog_id => $blog->id);
    my %arg = (sort => $app->get_posts_order_field, direction => 'descend');
    my $Limit = 20;
    $arg{limit} = $Limit + 1;
    $arg{offset} = $app->{param}{offset} || 0;
    my $iter = MT::Entry->load_iter(\%terms, \%arg);
    my $feed = $app->new_feed();
    my $uri = $app->base . $app->uri . '/blog_id=' . $blog->id;
    my $blogname = encode_text($blog->name, undef, 'utf-8');
    $feed->add_link({ rel => 'alternate', type => 'text/html',
                      href => $blog->site_url });
    $feed->title($blogname);
    $feed->add_link({ rel => 'service.post', type => 'application/x.atom+xml',
                      href => $uri, title => $blogname });
    $uri .= '/entry_id=';
    while (my $entry = $iter->()) {
        my $e = $app->new_with_entry($entry);
        $e->add_link({ rel => $app->edit_link_rel, type => $app->atom_x_content_type,
                       href => ($uri . $entry->id), title => encode_text($entry->title, undef,'utf-8') });
        $feed->add_entry($e);
    }
    ## xxx add next/prev links
    $app->response_content_type($app->atom_content_type);
    $feed->as_xml;
}

sub get_post {
    my $app = shift;
    my $blog = $app->{blog};
    my $entry_id = $app->{param}{entry_id}
        or return $app->error(400, "No entry_id");
    my $entry = MT::Entry->load($entry_id)
        or return $app->error(400, "Invalid entry_id");
    return $app->error(403, "Access denied")
        unless $app->{perms}->can_edit_entry($entry, $app->user);
    $app->response_content_type($app->atom_content_type);
    my $atom = $app->new_with_entry($entry);
    my $uri = $app->base . $app->uri . '/blog_id=' . $blog->id;
    $uri .= '/entry_id=';
    $atom->add_link({ rel => $app->edit_link_rel, type => $app->atom_x_content_type,
                      href => ($uri . $entry->id), title => encode_text($entry->title, undef,'utf-8') });
    $atom->as_xml;
}

sub delete_post {
    my $app = shift;
    my $blog = $app->{blog};
    my $entry_id = $app->{param}{entry_id}
        or return $app->error(400, "No entry_id");
    my $entry = MT::Entry->load($entry_id)
        or return $app->error(400, "Invalid entry_id");
    return $app->error(403, "Access denied")
        unless $app->{perms}->can_edit_entry($entry, $app->user);
    $entry->remove
        or return $app->error(500, $entry->errstr);
    $app->publish($entry, 1) or return $app->error(500, $app->errstr);
    '';
}

sub _upload_to_asset {
    my $app = shift;
    my $atom = $app->atom_body or return;
    my $blog = $app->{blog};
    my $user = $app->user;
    my %MIME2EXT = (
        'text/plain'         => '.txt',
        'image/jpeg'         => '.jpg',
        'video/3gpp'         => '.3gp',
        'application/x-mpeg' => '.mpg',
        'video/mp4'          => '.mp4',
        'video/quicktime'    => '.mov',
        'audio/mpeg'         => '.mp3',
        'audio/x-wav'        => '.wav',
        'audio/ogg'          => '.ogg',
        'audio/ogg-vorbis'   => '.ogg',
    );

    return $app->error(403, "Access denied") unless $app->{perms}->can_upload;
    my $content = $atom->content;
    my $type = $content->type
        or return $app->error(400, "content \@type is required");
    my $fname = $atom->title or return $app->error(400, "title is required");
    $fname = basename($fname);
    return $app->error(400, "Invalid or empty filename")
        if $fname =~ m!/|\.\.|\0|\|!;

    my $local_relative = File::Spec->catfile('%r', $fname);
    my $local = File::Spec->catfile($blog->site_path, $fname);
    my $fmgr = $blog->file_mgr;
    my($base, $path, $ext) = File::Basename::fileparse($local, '\.[^\.]*');
    $ext = $MIME2EXT{$type} unless $ext;
    my $base_copy = $base;
    my $ext_copy = $ext;
    $ext_copy =~ s/\.//;
    my $i = 1;
    while ($fmgr->exists($path . $base . $ext)) {
        $base = $base_copy . '_' . $i++;
    }
    $local = $path . $base . $ext;
    my $data = $content->body;
    defined(my $bytes = $fmgr->put_data($data, $local, 'upload'))
        or return $app->error(500, "Error writing uploaded file");

    eval { require Image::Size; };
    return $app->error(500, MT->translate("Perl module Image::Size is required to determine width and height of uploaded images.")) if $@;
    my ( $w, $h, $id ) = Image::Size::imgsize($local);

    require MT::Asset;
    my $asset_pkg = MT::Asset->handler_for_file($local);
    my $is_image  = defined($w)
      && defined($h)
      && $asset_pkg->isa('MT::Asset::Image');
    my $asset;
    if (!($asset = $asset_pkg->load(
                { file_path => $local, blog_id => $blog->id })))
    {
        $asset = $asset_pkg->new();
        $asset->file_path($local_relative);
        $asset->file_name($base.$ext);
        $asset->file_ext($ext_copy);
        $asset->blog_id($blog->id);
        $asset->created_by( $user->id );
    }
    else {
        $asset->modified_by( $user->id );
    }
    my $original = $asset->clone;
    my $url = '%r/' . $base . $ext;
    $asset->url($url);
    if ($is_image) {
        $asset->image_width($w);
        $asset->image_height($h);
    }
    $asset->mime_type($type);
    $asset->save;

    MT->run_callbacks(
        'api_upload_file.' . $asset->class,
        File => $local, file => $local,
        Url => $url, url => $url,
        Size => $bytes, size => $bytes,
        Asset => $asset, asset => $asset,
        Type => $asset->class, type => $asset->class,
        Blog => $blog, blog => $blog);
    if ($is_image) {
        MT->run_callbacks(
            'api_upload_image',
            File => $local, file => $local,
            Url => $url, url => $url,
            Size => $bytes, size => $bytes,
            Asset => $asset, asset => $asset,
            Height => $h, height => $h,
            Width => $w, width => $w,
            Type => 'image', type => 'image',
            ImageType => $id, image_type => $id,
            Blog => $blog, blog => $blog);
    }

    $asset;
}

sub handle_upload {
    my $app = shift;
    my $blog = $app->{blog};
    
    my $asset = $app->_upload_to_asset or return;

    my $link = XML::Atom::Link->new;
    $link->type($asset->mime_type);
    $link->rel('alternate');
    $link->href($asset->url);
    my $atom = XML::Atom::Entry->new;
    $atom->title($asset->file_name);
    $atom->add_link($link);
    $app->response_code(201);
    $app->response_content_type('application/x.atom+xml');
    $atom->as_xml;
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
