package RemoteTestApp2;

use Catalyst qw/
   Authentication
/;

use base qw/Catalyst/;
__PACKAGE__->engine_class('RemoteTestEngine');
__PACKAGE__->config(
    'Plugin::Authentication' => {
        default_realm => 'remote',
        realms => {
            remote => {
                credential => {
                    class => 'Remote',
                    allow_regexp => '^(bob|john|CN=.*)$',
                    deny_regexp=> 'denied',
                    cutname_regexp=> 'CN=(.*)/OU=Test',
                    source => 'SSL_CLIENT_S_DN',
                    username_field => 'my_user_name',
                },
                store => {
                    class => 'Null',
                },
            },
        },
    },
);

sub default : Local {
    my ( $self, $c ) = @_;
    if ($c->authenticate()) {
        $c->res->body( 
              'my_user_name:'
              . $c->user->{my_user_name}
        );
    }
    else {
        $c->res->body('FAIL');
        $c->res->status(403);
    }
}

sub public : Local {
    my ( $self, $c ) = @_;
    $c->res->body('OK');
}

__PACKAGE__->setup;

