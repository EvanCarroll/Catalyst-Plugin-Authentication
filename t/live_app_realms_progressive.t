use strict;
use warnings;

use Test::More tests => 7;

use lib 't/lib';
use Catalyst::Test qw/AuthRealmTestAppProgressive/;

ok(get("/progressive"), "get ok");
