#!/usr/bin/perl

use Test::More;
use lib "t/lib";
use MockResolver 'preflight';
# $MockResolver::verbose = 1;

use_ok('DNSCheck');

my $dns = DNSCheck->new({configdir => './t/config'})->dns();

isa_ok($dns,'DNSCheck::Lookup::DNS');

ok($dns->preflight_check('iis.se'), 'iis.se is a zone');
# ok(!$dns->preflight_check('argle-bargle glop glyf'), 'argle-bargle glop glyf is not a zone');
ok(!$dns->preflight_check('iis.example'), 'iis.example is not a zone');
ok($dns->preflight_check('XN--HLCJ6AYA9ESC7A'), 'XN--HLCJ6AYA9ESC7A is a zone');

done_testing();
