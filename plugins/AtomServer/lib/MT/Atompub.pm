
package MT::AtomServer::Init;

sub init_app {
    my ($plugin) = @_;
    return if !MT->instance->isa('MT::App::API');

    my $atom_apps = MT->config('AtomApp');
    return if !$atom_apps || !%$atom_apps;

    $plugin->registry({
        applications => {
            api => $atom_apps,
        },
    });
}

1;

