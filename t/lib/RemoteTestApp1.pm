package RemoteTestApp1;

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
        $c->res->body('User:' . $c->user->{username});
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

