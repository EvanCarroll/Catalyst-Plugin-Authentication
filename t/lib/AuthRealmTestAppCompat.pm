package AuthRealmTestAppCompat;
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

our $members = {
    bob => {
        password => "s00p3r"
    },
};

sub moose : Local {
	my ( $self, $c ) = @_;

    while ( my ($user, $info) = each %$members ) {
        
        my $ok = eval {
            $c->authenticate( 
                { username => $user, password => $info->{password} }, 
                'members' 
            ), 
        };
        
        ok( !$@,                "Test did not die: $@" );
        ok( $ok,                "user $user authentication" );
    }

	$c->res->body( "ok" );
}

__PACKAGE__->config->{'Plugin::Authentication'} = {  
    default_realm => 'members',
        members => {
            credential => {
                class => 'Password',
                password_field => 'password',
                password_type => 'clear'
            },
            store => {
                class => 'Minimal',
                users => $members,
            }
        },
    
};

__PACKAGE__->setup;
