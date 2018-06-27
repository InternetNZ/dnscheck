#!/usr/bin/perl -sw
#
# $Id$

require 5.008;
use warnings;
use strict;

use Test::More;
use lib "t/lib";

use DNSCheck::Config;
use Sys::Hostname;

######################################################################

my $conf = new_ok( 'DNSCheck::Config' => [
    configfile => './t/config/config.yaml',
    policyfile => './policy.yaml',
    localefile => './locale/en.yaml',
    siteconfigfile => './t/config/config.yaml',
    sitepolicyfile => './policy.yaml',
] );

SKIP: {
    skip "Failed to get an object to test", 4 unless defined( $conf );
    ok( ref( $conf )                  eq "DNSCheck::Config" );
    ok( ref( $conf->get( "net" ) )    eq "HASH" );
    ok( $conf->get( "hostname" )      eq hostname );
    is( scalar(keys(%{$conf->{locale}{messages}})), 298, 'Messages are there');
    is( scalar(keys(%{$conf->{loglevels}})), 223, 'Policy data is there');
}

new_ok( 'DNSCheck::Config' => [ configdir => './t/config', sitedir => './t/config' ] );
new_ok('DNSCheck::Config');

new_ok('DNSCheck::Config' => [locale => 'gurksallad', policyfile  => 'citronfromage']);
new_ok('DNSCheck::Config' => [ extras => {debug => 1} ] );
new_ok('DNSCheck::Config' => [ interactive => 1 ] );

eval { DNSCheck::Config->new( configfile => '/arglebargle/glop/glyf' ) };
like( $@, qr|Configuration file /arglebargle/glop/glyf not readable| );

done_testing;
