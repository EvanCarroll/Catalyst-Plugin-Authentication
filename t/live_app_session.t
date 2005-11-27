#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

BEGIN {
	eval { require Catalyst::Plugin::Session; require Catalyst::Plugin::Session::State::Cookie };
	plan skip_all => "This test needs Catalyst::Plugin::Session and Catalyst::Plugin::Session::State::Cookie installed" if $@;
	plan tests => 12;
}

{
	package AuthTestApp;
	use Catalyst qw/
		Session
		Session::Store::Dummy
		Session::State::Cookie

		Authentication
		Authentication::Store::Minimal
		Authentication::Credential::Password
	/;

	use Test::More;
	use Test::Exception;

	use Digest::MD5 qw/md5/;

	our $users;

	sub moose : Local {
		my ( $self, $c ) = @_;

		ok(!$c->sessionid, "no session id yet");
		ok(!$c->user, "no user yet");
		ok($c->login( "foo", "s3cr3t" ), "can login with clear");
		is( $c->user, $users->{foo}, "user object is in proper place");
	}

	sub elk : Local {
		my ( $self, $c ) = @_;

		ok( $c->sessionid, "session ID was restored" );
		ok( $c->user, "a user was also restored");
		is_deeply( $c->user, $users->{foo}, "restored user is the right one (deep test - store might change identity)" );

		$c->delete_session("bah");
	}

	sub fluffy_bunny : Local {
		my ( $self, $c ) = @_;

		ok( !$c->sessionid, "no session ID was restored");
		ok( !$c->user, "no user was restored");
	}

	__PACKAGE__->config->{authentication}{users} = $users = {
		foo => {
			password => "s3cr3t",
		},
	};

	__PACKAGE__->setup;
}

use Test::WWW::Mechanize::Catalyst qw/AuthTestApp/; # for the cookie support

my $m = Test::WWW::Mechanize::Catalyst->new;

$m->get_ok("http://localhost/moose", "get ok");
$m->get_ok("http://localhost/elk", "get ok");
$m->get_ok("http://localhost/fluffy_bunny", "get ok");

