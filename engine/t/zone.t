#!/usr/bin/perl
#
# $Id$

require 5.008;
use warnings;
use strict;

use Test::More;
use lib "t/lib";

use MockResolver 'zone', {multiple => 1};
# use MockBootstrap 'zone', {multiple => 1};

use_ok 'DNSCheck';

######################################################################

sub set_flags {
    my ($obj, $v4, $v6) = @_;
    
    my $net = $obj->config->get("net");

    $net->{ipv4} = $v4;
    $net->{ipv6} = $v6;

    $obj->config->put('net', $net);
}

my $dc = new_ok('DNSCheck' => [{ configdir => './t/config' }]);

if (!defined($dc)) {
    done_testing();
    exit;
}

# Not very good tests.
ok(defined($dc->zone->test("iis.se")));
$dc->log_nameserver_times('iis.se');
my @res          = @{ $dc->logger->export };
my $result_count = scalar(@res);
ok(abs($result_count - 880) < 50,
    "Got $result_count lines from logger.");
my $info_count = scalar(grep { $_->[2] eq 'INFO' } @res);
ok(abs($info_count - 144) < 40, "$info_count INFO-level results.");
ok($dc->logger->count_info == $info_count);
my $notice_count = scalar(grep { $_->[2] eq 'NOTICE' } @res);
ok(abs($notice_count - 12) < 5, "$notice_count NOTICE-level results.");
ok($dc->logger->count_notice == $notice_count);
my $warning_count = scalar(grep { $_->[2] eq 'WARNING' } @res);
ok(abs($warning_count - 5) < 5,
    "$warning_count WARNING-level results.");
ok($dc->logger->count_warning == $warning_count);
my $debug_count = scalar(grep { $_->[2] eq 'DEBUG' } @res);
ok(abs($debug_count - 730) < 50, "$debug_count DEBUG-level results.");
ok($dc->logger->count_debug == $debug_count);

my %tag = map {$_->[3] => 1} @{$dc->logger->export};
ok($tag{'NSTIME:AVERAGE'}, 'Timing information is present');

# Test the test-disabling function
$dc = new_ok('DNSCheck' => [{ configdir => './t/config' }]);
$dc->config->put('disable', {zone => {test => 1}});
$dc->zone->test('nic.se');
is_deeply($dc->logger->export, [], 'Test disabled');

# Test disabling IP versions
$dc = new_ok('DNSCheck' => [{ configdir => './t/config' }]);
set_flags($dc, undef, undef, undef);
is($dc->config->get("net")->{ipv4}, undef, 'IPv4 flag set correctly');
is($dc->config->get("net")->{ipv6}, undef, 'IPv6 flag set correctly');
$dc->zone->test('nic.se');

is_deeply(
    [map {$_->[3]} @{$dc->logger->export}],
    [
    "ZONE:BEGIN",
    "DELEGATION:BEGIN",
    "DNS:GET_NS_AT_PARENT",
    "DNS:QUERY_PARENT",
    "DNS:QUERY_PARENT_NOCACHE",
    "DNS:FIND_PARENT",
    "DNS:FIND_PARENT_BEGIN",
    "DNS:NXDOMAIN",
    "DNS:NO_PARENT",
    "DELEGATION:NOT_FOUND_AT_PARENT",
    'DNS:QUERY_RESOLVER',
    'DNS:QUERY_RESOLVER',
    "DELEGATION:END",
    "ZONE:FATAL_DELEGATION",
    "ZONE:END",
    ],
    'IPv4 and IPv6 disabled');

$dc = new_ok('DNSCheck' => [{ configdir => './t/config' }]);
set_flags($dc, undef, 1, undef);
$dc->zone->test('iis.se');
ok(scalar(@{$dc->logger->export}) > 540, 'IPv6-only tests');

$dc = new_ok('DNSCheck' => [{ configdir => './t/config' }]);
set_flags($dc, 1, undef, undef);
$dc->zone->test('iis.se');
ok(scalar(@{$dc->logger->export}) > 580, 'IPv4-only tests');

done_testing();
