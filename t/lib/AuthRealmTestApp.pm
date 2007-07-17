package AuthRealmTestApp;
use warnings;
use strict;

use Catalyst qw/Authentication/;

use Test::More;
use Test::Exception;

our $members = {
    bob => {
        password => "s00p3r"
    },
    william => {
        password => "s3cr3t"
    }
};

our $admins = {
    joe => {
        password => "31337"
    }
};

sub moose : Local {
	my ( $self, $c ) = @_;

	ok(!$c->user, "no user");

    while ( my ($user, $info) = each %$members ) {
        
        ok( 
            $c->authenticate( 
                { username => $user, password => $info->{password} }, 
                'members' 
            ), 
            "user $user authentication" 
        );

        # check existing realms
        ok( $c->user_in_realm('members'), "user in members realm");
        ok(!$c->user_in_realm('admins'),  "user not in admins realm");

        # check an invalid realm
        ok(!$c->user_in_realm('foobar'), "user not in foobar realm");

        # check if we've got the right user
        is( $c->user, $info, "user object is in proper place");

        $c->logout;

	    # sanity check
        ok(!$c->user, "no more user after logout");

    }

    while ( my ($user, $info) = each %$admins ) {
        
        ok( 
            $c->authenticate( 
                { username => $user, password => $info->{password} }, 
                'admins' 
            ), 
            "user $user authentication" 
        );

        # check existing realms
        ok(!$c->user_in_realm('members'), "user not in members realm");
        ok( $c->user_in_realm('admins'),  "user in admins realm");

        # check an invalid realm
        ok(!$c->user_in_realm('foobar'), "user not in foobar realm");

        # check if we've got the right user
        is( $c->user, $info, "user object is in proper place");

        $c->logout;

	    # sanity check
        ok(!$c->user, "no more user after logout");

    }

	$c->res->body( "ok" );
}

__PACKAGE__->config->{authentication} = {  
    default_realm => 'members',
    realms => {
        members => {
            credential => {
                class => 'Password',
                password_field => 'password',
                password_type => 'clear'
            },
            store => {
                class => 'Minimal',
                users => $members             
            }
        },
        admins => {
            credential => {
                class => 'Password',
                password_field => 'password',
                password_type => 'clear'
            },
            store => {
                class => 'Minimal',
                users => $admins               
            }
        }
    }
};

__PACKAGE__->setup;
