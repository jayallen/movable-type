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
    $app->{requires_login} = 0;
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
        my $subapp = $apps->{$subapp};
        if ($subapp && (my $class = $subapp->{class})) {
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

            # Set the auth handlers here, while we're looking in the registry.
            $app->auth_drivers($subapp->{auth});
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

sub auth_drivers {
    my $app = shift;
    ($app->{auth_drivers}) = @_ if @_;
    return @{ $app->{auth_drivers} || [] };
}

sub login_failure {
    my $app = shift;
    my ($code, $phrase) = @_;
    $code ||= 401;
    $phrase ||= 'Unauthorized';

    my @auth_headers;
    for my $driver ($app->auth_drivers) {
        eval "require $driver;";
        next if $@;
        push @auth_headers, $driver->auth_header;
    }
    #TODO: does not work - set_header doesn't accept the same header twice
    #$app->set_header('WWW-Authenticate', $_) for @auth_headers;
    $app->set_header('WWW-Authenticate', $auth_headers[0]);

    my $err = $app->errstr || "Authorization required.";
    $app->response_code($code);
    $app->response_message($phrase);
    return $app->error($err);
}

sub login {
    my $app = shift;

    my ($driver, $cred);
    DRIVER: for my $try_driver ($app->auth_drivers) {
        eval "require $try_driver;";
        next if $@;
        $cred = $try_driver->fetch_credentials({ app => $app });
        $driver = $try_driver, last DRIVER if $cred && %$cred;
    }
    return $app->login_failure() if !$driver;

    $cred->{app} = $app unless exists $cred->{app};
    my $result = $driver->validate_credentials($cred);
    return $app->login_failure()
      if $result != MT::Auth->SUCCESS()
      && $result != MT::Auth->NEW_LOGIN();

    ## update session so the user will be counted as active
    require MT::Session;
    my $sess_active = MT::Session->load({ kind => 'UA', name => $app->user->id });
    if (!$sess_active) {
        $sess_active = MT::Session->new;
        $sess_active->id($app->make_magic_token());
        $sess_active->kind('UA'); # UA == User Activation
        $sess_active->name($app->user->id);
    }
    $sess_active->start(time);
    $sess_active->save;
    return $app->user;
}

sub is_authorized {
    my $app = shift;
    return $app->user ? 1 : 0;
}

1;

