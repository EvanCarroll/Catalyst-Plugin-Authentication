#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

BEGIN {
	eval { require Test::WWW::Mechanize::Catalyst; require Catalyst::Plugin::Session; require Catalyst::Plugin::Session::State::Cookie };
	plan skip_all => "This test needs Test::WWW::Mechanize::Catalyst, Catalyst::Plugin::Session and Catalyst::Plugin::Session::State::Cookie installed" if $@;
	plan tests => 20;
}

use lib 't/lib';
use Test::WWW::Mechanize::Catalyst qw/AuthSessionTestApp/; # for the cookie support

my $m = Test::WWW::Mechanize::Catalyst->new;

$m->get_ok("http://localhost/moose", "get ok");
$m->get_ok("http://localhost/elk", "get ok");
$m->get_ok("http://localhost/fluffy_bunny", "get ok");
$m->get_ok("http://localhost/possum", "get ok");
$m->get_ok("http://localhost/butterfly", "get ok");
