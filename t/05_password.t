use strict;
use warnings;

use Test::More tests => 11;
use Test::Exception;
use Test::MockObject;

# 1,2
my $m; BEGIN { use_ok($m = "Catalyst::Authentication::Credential::Password") }
can_ok($m, "authenticate");

my $app = Test::MockObject->new;
my $realm = Test::MockObject->new;
my $user = Test::MockObject->new;
our ($user_get_password_field_name, $user_password );
$user->mock('get' => sub { $user_get_password_field_name = $_[1]; return $user_password });

# 3-6 # Test clear passwords if you mess up the password_field
{
    local $user_password = undef;        # The user returns an undef password, 
    local $user_get_password_field_name; # as there is no field named 'mistyped'
    my $config = { password_type => 'clear', password_field => 'mistyped' };
    my $i; lives_ok { $i = $m->new($config, $app, $realm) } 'Construct instance';
    ok($i, 'Have instance');
    my $r = $i->check_password($user, { username => 'someuser', password => 'password' });
    is($user_get_password_field_name, 'mistyped', 
        '(Incorrect) field name from config correctly passed to user');
    ok(! $r, 'Authentication unsuccessful' );
}

# 7-11 # Test clear passwords working, and not working
{
    local $user_password = 'mypassword';         
    local $user_get_password_field_name;
    my $config = { password_type => 'clear', password_field => 'the_password_field' };
    my $i; lives_ok { $i = $m->new($config, $app, $realm) } 'Construct instance';
    ok($i, 'Have instance');
    my $r = $i->check_password($user, { username => 'someuser', the_password_field => 'mypassword' });
    is($user_get_password_field_name, 'the_password_field', 
        'Correct field name from config correctly passed to user');
    ok( $r, 'Authentication successful with correct password' );
    $r = $i->check_password($user, { username => 'someuser', the_password_field => 'adifferentpassword' });
    ok( ! $r, 'Authentication ussuccessful with incorrect password' );
}
