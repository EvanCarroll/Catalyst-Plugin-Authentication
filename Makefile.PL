use inc::Module::Install 0.87;

if ( $Module::Install::AUTHOR ) {
    system( 'pod2text lib/Catalyst/Plugin/Authentication.pm > README' )
        and die;
    require Module::Install::AuthorTests;
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
test_requires 'Class::MOP';
test_requires 'Moose';

author_tests 't/author';

auto_install;
resources repository => 'http://dev.catalyst.perl.org/repos/Catalyst/Catalyst-Plugin-Authentication/0.10000/trunk';

WriteAll;
