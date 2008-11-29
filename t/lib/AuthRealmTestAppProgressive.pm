package AuthRealmTestAppProgressive;
use warnings;
use strict;

### using A::Store::minimal with new style realms
### makes the app blow up, since c::p::a::s::minimal
### isa c:a::s::minimal, and it's compat setup() gets
### run, with an unexpected config has (realms on top,
### not users). This tests makes sure the app no longer
### blows up when this happens.
use Catalyst qw/
    Authentication
    Authentication::Store::Minimal
/;

use Test::More;
use Test::Exception;

our %members = (
    'members' => {
        bob => { password => "s00p3r" }
    },
    'other' => {
        sally => { password => "s00p3r" }
    },
);

__PACKAGE__->config->{'Plugin::Authentication'} = {
    default_realm => 'progressive',
    progressive => {
        class  => 'Progressive',
        realms => [ 'other', 'members' ],
    },
    other => {
        credential => {
            class => 'Password',
            password_field => 'password',
            password_type  => 'clear'
        },
        store => {
            class => 'Minimal',
            users => $members{other},
        }
    },
    members => {
        credential => {
            class => 'Password',
            password_field => 'password',
            password_type => 'clear'
        },
        store => {
            class => 'Minimal',
            users => $members{members},
        }
    },
};

sub progressive : Local {
	my ( $self, $c ) = @_;

    foreach my $realm ( keys %members ) {
        while ( my ( $user, $info ) = each %{$members{$realm}} ) {
            my $ok = eval {
                $c->authenticate(
                    { username => $user, password => $info->{password} },
                ); 
            };
            ok( !$@, "authentication passed." );
            ok( $ok, "user authenticated" );
            ok( $c->user_in_realm($realm), "user in proper realm" );
        }
    }
	$c->res->body( "ok" );
}

__PACKAGE__->setup;

