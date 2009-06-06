use inc::Module::Install 0.87;

if( -e 'MANIFEST.SKIP' ) {
    system( 'pod2text lib/Catalyst/Plugin/Authentication.pm > README' );
}

perl_version '5.008001';

name 'Catalyst-Plugin-Authentication';
all_from 'lib/Catalyst/Plugin/Authentication.pm';

requires 'Catalyst::Runtime';
requires 'Class::Inspector';
requires 'MRO::Compat';
requires 'Catalyst::Plugin::Session' => '0.10';

test_requires 'Test::More';
test_requires 'Test::Exception';
test_requires 'Test::MockObject';

auto_install;
WriteAll;
