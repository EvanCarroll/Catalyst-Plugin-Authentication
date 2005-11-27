use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name        => 'Catalyst::Plugin::Authentication',
    requires           => {
        'perl'     => '5.8.1',
        'Catalyst' => '5.49',
    },
    reccomends    => { 'Want' => 0, },
    create_readme => 1,
    sign          => 1,
);
$build->create_build_script;

