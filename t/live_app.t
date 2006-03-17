#!/usr/bin/perl

use strict;
use warnings;

use Test::More 'no_plan';

{
	package AuthTestApp;
	use Catalyst qw/
		Authentication
		Authentication::Store::Minimal
		Authentication::Credential::Password
	/;

	use Test::More;
	use Test::Exception;

	use Digest::MD5 qw/md5/;
    use Digest::SHA1 qw/sha1_base64/;

	our $users;

	sub moose : Local {
		my ( $self, $c ) = @_;

		ok(!$c->user, "no user");
		ok($c->login( "foo", "s3cr3t" ), "can login with clear");
		is( $c->user, $users->{foo}, "user object is in proper place");

		ok( !$c->user->roles, "no roles for foo" );
		my @new = qw/foo bar gorch/;
		$c->user->roles( @new );
		is_deeply( [ $c->user->roles ], \@new, "roles set as array");

		$c->logout;
		ok(!$c->user, "no more user, after logout");


		ok($c->login( "bar", "s3cr3t" ), "can login with crypted");
		is( $c->user, $users->{bar}, "user object is in proper place");
		$c->logout;

		ok($c->login("gorch", "s3cr3t"), "can login with hashed");
		is( $c->user, $users->{gorch}, "user object is in proper place");
		$c->logout;

		ok($c->login("shabaz", "s3cr3t"), "can login with base64 hashed");
		is( $c->user, $users->{shabaz}, "user object is in proper place");
		$c->logout;

		ok($c->login("sadeek", "s3cr3t"), "can login with padded base64 hashed");
		is( $c->user, $users->{sadeek}, "user object is in proper place");
		$c->logout;

		ok(!$c->login( "bar", "bad pass" ), "can't login with bad password");
		ok(!$c->user, "no user");

		throws_ok { $c->login( "baz", "foo" ) } qr/support.*mechanism/, "can't login without any supported mech";

		$c->res->body( "ok" );
	}

	__PACKAGE__->config->{authentication}{users} = $users = {
		foo => {
			password => "s3cr3t",
		},
		bar => {
			crypted_password => crypt("s3cr3t", "x8"),
		},
		gorch => {
			hashed_password => md5("s3cr3t"),
			hash_algorithm => "MD5",
		},
        shabaz => {
            hashed_password => sha1_base64("s3cr3t"),
            hash_algorithm => "SHA-1"
        },
        sadeek => {
            hashed_password => sha1_base64("s3cr3t").'=',
            hash_algorithm => "SHA-1"
        },
		baz => {},
	};

	__PACKAGE__->setup;
}

use Catalyst::Test qw/AuthTestApp/;

ok( get("/moose"), "get ok");
