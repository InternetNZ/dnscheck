#!/usr/bin/perl -sw
#
# $Id$

require 5.008;
use warnings;
use strict;
use lib "t/lib";

use Test::More;

use MockResolver 'find_parent', {multiple => 1};
# use MockBootstrap 'find_parent', {multiple => 1};
use DNSCheck;

######################################################################

my $check = new DNSCheck({configdir => './t/config'});
my $dns   = $check->dns;

######################################################################

ok(!$dns->find_parent("citron.fromage.gobbledygook.6f3899904701b0ce2835d82493c0212babf875c7", "IN"));
is($dns->find_parent("se",           "IN"), ".");
is($dns->find_parent("iis.se",       "IN"), "se");
is($dns->find_parent("narnia.pp.se", "IN"), "se");
is($dns->find_parent("example.com",  "IN"), "com");
is($dns->find_parent("brixtal.se",   "IN"), "se");
is($dns->find_parent("tboerner.eu",  "IN"), "eu");

is($dns->find_parent("pewc.se",      "IN"), "se");
is($dns->find_parent("xtent.se",     "IN"), "se");

is($dns->find_parent("arpa", "IN"), ".");

done_testing;