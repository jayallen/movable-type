# Movable Type (r) Open Source (C) 2001-2008 Six Apart, Ltd.
# This program is distributed under the terms of the
# GNU General Public License, version 2.
#
# $Id$

package MT::App::API;
use strict;

use base qw( MT::App );

sub init {
    my $app = shift;
    $app->{no_read_body} = 1
        if $app->request_method eq 'POST' || $app->request_method eq 'PUT';
    $app->SUPER::init(@_) or return $app->error("Initialization failed");
    $app->request_content
        if $app->request_method eq 'POST' || $app->request_method eq 'PUT';
    $app->add_methods(
        handle => \&handle,
    );
    $app->{default_mode} = 'handle';
    $app->{is_admin} = 0;
    $app->{warning_trace} = 0;
    $app;
}

sub handle {
    my $app = shift;

    my $out = eval {
        (my $pi = $app->path_info) =~ s!^/!!;
        my($subapp, @args) = split /\//, $pi;
        $app->{param} = {};
        for my $arg (@args) {
            my($k, $v) = split /=/, $arg, 2;
            $app->{param}{$k} = $v;
        }

        my $apps = $app->registry(qw( applications api ));
        if (my $class = $apps->{$subapp}) {
            if (ref $class) {
                # TODO: Dynamically generate some api subclass for a set of
                # methods specified in registry?
                die "Partially specified endpoints not yet supported\n";
            }
            else {
                eval "require $class" or die $@;
            }

            # Rebless the app into that subclass.
            bless $app, $class;
        }
        my $out = $app->handle_request;
        return unless defined $out;

        return $out;
    };
    if ((my $e = $@) || !defined $out) {
        $app->error(500, "Internal Error");
        return $app->show_error($e);
    }
    return $out;
}

sub handle_request {
    my $app = shift;
    my $method = uc $app->request_method;

    my @methods = $app->supported_methods();
    if (!grep { $_ eq $method } @methods) {
        $app->error(405, 'Method Not Allowed');
        $app->set_header( Allow => join q{, }, @methods );
        return $app->show_error('Method not supported on this resource');
    }

    $method = "handle_$method";
    return $app->$method();
}

sub supported_methods { qw( GET HEAD OPTIONS POST PUT DELETE ) }
sub handle_GET     { 1 }
sub handle_POST    { 1 }
sub handle_PUT     { 1 }
sub handle_HEAD    { 1 }
sub handle_OPTIONS { 1 }
sub handle_DELETE  { 1 }

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
    my ($err) = @_;
    $app->response_content_type('text/plain');
    return $app->translate('Error: [_1]', $err);
}

sub auth_drivers {
    qw( MT::Auth::WSSE );
}

sub authenticate {
    my $app = shift;
    my ($driver, $cred);
    DRIVER: for my $try_driver ($app->auth_drivers()) {
        $cred = $try_driver->fetch_credentials({ app => $app });
        $driver = $try_driver, last DRIVER if $cred && %$cred;
    }
    return if !$driver;

    my $result = $driver->validate_credentials($cred);
    return if $result != MT::Auth->SUCCESS()
           && $result != MT::Auth->NEW_LOGIN();

    ## update session so the user will be counted as active
    require MT::Session;
    my $sess_active = MT::Session->load( { kind => 'UA', name => $app->user->id } );
    if (!$sess_active) {
        $sess_active = MT::Session->new;
        $sess_active->id($app->make_magic_token());
        $sess_active->kind('UA'); # UA == User Activation
        $sess_active->name($app->user->id);
    }
    $sess_active->start(time);
    $sess_active->save;
    return 1;
}

sub is_authorized {
    my $app = shift;
    return $app->error(401, 'Unauthorized')
        if !$app->user;
    return 1;
}

1;

