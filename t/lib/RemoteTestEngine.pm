package RemoteTestEngine;
use base 'Catalyst::Engine::CGI';

our $REMOTE_USER;
our $SSL_CLIENT_S_DN;

sub env {
    my $self = shift;
    my %e = %ENV;
    $e{REMOTE_USER} = $REMOTE_USER;
    $e{SSL_CLIENT_S_DN} = $SSL_CLIENT_S_DN;
    return \%e;    
};

1;
