#!/usr/bin/perl

use Test::More;
use lib "t/lib";

# use MockBootstrap ('delegation', {multiple => 1});
use MockResolver ('delegation', {multiple => 1});

use_ok('DNSCheck');

my $dc = DNSCheck->new({configdir => './t/config'});

# Good zone
my ($errors, $testable) = $dc->delegation->test('iis.se', ['ns1.google.com']);

is( $errors, 0, 'No errors');
ok( $testable, 'Zone is testable');

my %tags = map {$_->[3] => 1} @{$dc->logger->export};

foreach my $m (qw[GLUE_FOUND_AT_PARENT MATCHING_GLUE NS_HISTORY ]) {
    ok($tags{"DELEGATION:$m"}, "DELEGATION:$m");
}
$dc->logger->clear;

# Not good zone
($errors, $testable) = $dc->delegation->test('bildarkiv.se');

is( $errors, 1, "$errors error(s)");
ok( !$testable, 'Zone is not testable');

%tags = map {$_->[3] => 1} @{$dc->logger->export};

foreach my $m (qw[NS_AT_PARENT NOT_FOUND_AT_CHILD BROKEN_BUT_FUNCTIONAL]) {
    ok($tags{"DELEGATION:$m"}, "DELEGATION:$m");
}
$dc->logger->clear;

# Other not good zone
($errors, $testable) = $dc->delegation->test('crystone.se');

ok( $errors == 2, "$errors error(s)");
ok( $testable, 'Zone is testable');

%tags = map {$_->[3] => 1} @{$dc->logger->export};

foreach my $m (qw[NS_AT_PARENT NS_AT_CHILD EXTRA_NS_PARENT NO_COMMON_NS_NAMES EXTRA_NS_CHILD NO_NS_IPV6 MIN_REFERRAL_SIZE_OK ]) {
    ok($tags{"DELEGATION:$m"}, "DELEGATION:$m");
}
$dc->logger->clear;

# Another one

($errors, $testable) = $dc->delegation->test('sig.se');
ok( $errors == 2, "$errors error(s)");
ok( $testable, 'sig.se is testable');

%tags = map {$_->[3] => 1} @{$dc->logger->export};

foreach my $m (qw[INCONSISTENT_GLUE]) {
    ok($tags{"DELEGATION:$m"}, "DELEGATION:$m");
}
$dc->logger->clear;

# DNS05 bug

($errors, $testable) = $dc->delegation->test('wiccainfo.se');
ok($testable, 'testable');
ok($errors == 0, 'no errors');
%tags = map {$_->[3] => $_} @{$dc->logger->export};

foreach my $m (qw[GLUE_SKIPPED]) {
    ok($tags{"DELEGATION:$m"}, "DELEGATION:$m");
    is($tags{'DELEGATION:GLUE_SKIPPED'}[7], 'out-of-zone', 'skipped for right reason');
}
$dc->logger->clear;

# And another
($errors, $testable) = $dc->delegation->test('uddevalla.se');

%tags = map {$_->[3] => 1} @{$dc->logger->export};

foreach my $m (qw[INZONE_NS_WITHOUT_GLUE]) {
    ok($tags{"DELEGATION:$m"}, "DELEGATION:$m");
}
$dc->logger->clear;

my %data = (
          'eeeee.ns.se' => [
                             '81.228.10.57'
                           ],
          'aaaaaaaaa.ns.se' => [
                                 '2a01:3f0:0:301::53',
                                 '192.36.144.107'
                               ],
          'ggg.ns.se' => [
                           '2001:6b0:e:3::1',
                           '130.239.5.114'
                         ],
          'ffff.ns.se' => [
                            '2a01:3f0:0:305::53',
                            '192.71.53.53'
                          ],
          'j.ns.se' => [
                         '199.254.63.1',
                         '199.254.63.2',
                         '199.254.63.3'
                       ],
          'ii.ns.se' => [
                          '2001:67c:1010:5::53',
                          '194.146.106.22'
                        ],
          'ccccccc.ns.se' => [
                               '2001:67c:2554:301::53',
                               '192.36.135.107'
                             ],
          'dddddd.ns.se' => [
                              '81.228.8.16'
                            ],
          'bbbbbbbb.ns.se' => [
                                '2001:67c:254c:301::53',
                                '192.36.133.107'
                              ]
        );
is($dc->delegation->min_packet_length('se', %data), 498, 'Minimum referral size');

done_testing();
