#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib "t/lib";
# use MockBootstrap 'logger';
use MockResolver 'logger';
use File::Temp 'tempfile';

use_ok( 'DNSCheck' );
my $dc = new_ok( 'DNSCheck' => [ { configdir => './t/config' } ] );
$dc->config->{disable}{mail}{test} = 0;
$dc->logger->set_filter( 'SOA:BEGIN', ['iis.se'], 'CRITICAL' );

my $log = $dc->logger;

eval {
    $log->callback('not a coderef');
};
like($@, qr[Attempted to set non-coderef as logging callback], 'Callback protection works');
my $cb_counter = 0;
$log->callback( sub {$cb_counter += 1});

$dc->soa->test( 'iis.se' );

is($cb_counter, 141, 'Callback ran expected number of times');

isa_ok( $log,         'DNSCheck::Logger' );
isa_ok( $log->locale, 'DNSCheck::Locale' );

is( $log->count_critical, 1,   'Critical errors' );
is( $log->count_error,    0,   'Errors' );
is( $log->count_warning,  0,   'Warnings' );
is( $log->count_notice,   1,   'Notices' );
is( $log->count_info,     33,  'Informational messages' );
is( $log->count_debug,    106, 'Debug messages' );

my $msg = $log->export;
my $msg_hash = $log->export_hash;
is( scalar( @$msg ), 141, 'Correct number of entries dumped from export' );
is(
    scalar( @$msg_hash ), scalar( @$msg ),
    'Same number of entries dumped from export_hash and export'
);

foreach my $obj (@$msg) {
    isa_ok($obj, 'ARRAY');
}

foreach my $obj (@$msg_hash) {
    isa_ok($obj, 'HASH');
    is_deeply(
        [sort keys %$obj],
        [sort qw( timestamp level tag module_id parent_module_id arg logname )],
        'Correct key list in exported hash'
    );
    ok($obj->{tag}, 'Message has a tag');
}

my $count = 0;
$count++ while ( $log->get_next_entry );
is( $count, 141, 'Iterator saw all messages' );

{
    local *STDERR;
    my ( $fh, $filename ) = tempfile();
    open STDERR, '>', $filename or die $!;
    $log->dump;
    STDERR->flush;
    my @lines = <$fh>;
    is( scalar( @lines ), 141, 'dump printed correct number of lines' );
    close( $fh );
    unlink( $filename );
}

{
    local *STDOUT;
    my ( $fh, $filename ) = tempfile();
    open STDOUT, '>', $filename or die $!;
    $log->print;
    STDOUT->flush;
    my @lines = <$fh>;
    is( scalar( @lines ), 35, 'print printed correct number of lines' );
    close( $fh );
    unlink( $filename );
}

$dc = new_ok( 'DNSCheck' => [ { configdir => './t/config', localefile => 'locale/en.yaml' } ] );
$dc->logger->set_filter( 'SOA:BEGIN', ['iis.se'], 'CRITICAL' );
$dc->logger->remove_filters_for('SOA:BEGIN');
$dc->soa->test( 'iis.se' );
{
    local *STDOUT;
    my ( $fh, $filename ) = tempfile();
    open STDOUT, '>', $filename or die $!;
    $dc->logger->logname( 'gurksallad' );
    $dc->logger->print;
    STDOUT->flush;
    my @lines = <$fh>;
    is( scalar( @lines ), 19, 'print printed correct number of lines' );
    is( $lines[0], "  0.000: gurksallad INFO Begin testing SOA parameters for iis.se.\n", 'String translated OK' );
    close( $fh );
    unlink( $filename );
}

$dc = new_ok( 'DNSCheck' => [ { configdir => './t/config', localefile => 'locale/en.yaml' } ] );
$dc->config->put( 'loglevels', undef );
$dc->logger->logname( 'gurksallad' );
$dc->soa->test( 'iis.se' );
{
    local *STDERR;
    my ( $fh, $filename ) = tempfile();
    open STDERR, '>', $filename or die $!;
    $dc->logger->dump;
    STDERR->flush;
    my @lines = <$fh>;
    is( scalar( @lines ), 81, 'dump printed correct number of lines' );
    like( $lines[0], qr/gurksallad/, 'logname correct' );
    close( $fh );
    unlink( $filename );
}

{
    local *STDOUT;
    my ( $fh, $filename ) = tempfile();
    open STDOUT, '>', $filename or die $!;
    $dc = new_ok( 'DNSCheck' => [ { configfile => './t/config/config_filter.yaml', localefile => 'locale/sv.yaml' } ] );
    $dc->logger->logname( 'citronfromage' );
    is( $dc->logger->logname, 'citronfromage' );
    $dc->logger->{interactive} = 1;
    $dc->soa->test( 'iis.se' );
    STDOUT->flush;
    my @lines = <$fh>;
    is( scalar( @lines ), 19, 'interactive print printed correct number of lines' );
    like( $lines[0], qr/  0.(\d+): citronfromage WARNING B.rjar testa SOA-parametrar f.r iis.se./, 'String translated OK' );

    close( $fh );
    unlink( $filename );
}

$dc = new_ok( 'DNSCheck' => [ { configfile => './t/config/config_filter.yaml' } ] );
$dc->soa->test('14.109.in-addr.arpa');
my %modified = map {$_->{arg}[0] => $_->{level}} grep {$_->{tag} eq 'ADDRESS:BEGIN'} @{$dc->logger->export_hash};
is($modified{'109.0.74.131'}, 'NOTICE', 'Filter-set level 1 OK');
is($modified{'109.0.74.133'}, 'WARNING', 'Filter-set level 2 OK');

done_testing();
