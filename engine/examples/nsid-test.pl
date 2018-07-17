#!/usr/bin/perl

use Data::Dumper;
use Net::DNS;

my $resolver = new Net::DNS::Resolver;
$resolver->nameserver("ns2.dns.net.nz");
$resolver->debug(1);

my $query = Net::DNS::Packet->new("nz.", "SOA", "IN");
$query->header->rd(0);
$query->edns->size(2048);
$query->edns->option( NSID => 0x00 );

print Dumper($query);

my $response = $resolver->send($query);

print Dumper($response);
$a =  $response->edns->option(3);
print Dumper($a)
