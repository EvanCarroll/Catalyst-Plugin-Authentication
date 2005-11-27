#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 7;
use Test::Exception;

my $m; BEGIN { use_ok($m = "Catalyst::Plugin::Authentication::User") }

{
	package SomeUser;
	use base $m;

	sub new { bless {}, shift };

	sub supported_features {
		{
			feature => {
				subfeature => 1,
				unsupported_subfeature => 0,
			},
			top_level => 1,
		}
	}
}

my $o = SomeUser->new;

can_ok( $m, "supports" );

ok( $o->supports("top_level"), "simple top level feature check");
ok( $o->supports(qw/feature subfeature/), "traversal");
ok( !$o->supports(qw/feature unsupported_subfeature/), "traversal terminating in false");

lives_ok {
	$o->supports("bad_key");
} "cant check for non existent feature";

dies_ok {
	$o->supports(qw/bad_key subfeature/)
} "but can't traverse into one";


