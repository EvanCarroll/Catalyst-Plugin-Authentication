use strict;
use warnings;

use Test::More 'no_plan';


my $m; BEGIN { use_ok($m = "Catalyst::Authentication::Credential::Password") }

can_ok($m, "login");


