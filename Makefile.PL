use inc::Module::Install 0.67;

name 'Catalyst-Plugin-Authentication';
all_from 'lib/Catalyst/Plugin/Authentication.pm';

perl_version '5.8.1';

requires 'Catalyst::Runtime';
requires 'Class::Inspector';
requires 'Catalyst::Plugin::Session' => '0.10';

auto_install;
WriteAll;
