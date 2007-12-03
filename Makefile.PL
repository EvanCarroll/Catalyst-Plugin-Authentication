use inc::Module::Install 0.67;

if( -e 'MANIFEST.SKIP' ) {
    system( 'pod2text lib/Catalyst/Plugin/Authentication.pm > README' );
}

name 'Catalyst-Plugin-Authentication';
all_from 'lib/Catalyst/Plugin/Authentication.pm';

perl_version '5.8.1';

requires 'Catalyst::Runtime';
requires 'Class::Inspector';
requires 'Catalyst::Plugin::Session' => '0.10';

test_requires 'Test::More';

auto_install;
WriteAll;
