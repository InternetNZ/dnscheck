#!/usr/bin/perl
#
# $Id$
#
# Copyright (c) 2007 .SE (The Internet Infrastructure Foundation).
#                    All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
######################################################################

package DNSCheck::Test::Consistency;

use 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';

use Net::IP 1.25;
use Digest::SHA qw(sha1 sha1_hex sha1_base64);

######################################################################

sub test {
    my $self = shift;
    my $zone = shift;

    my $parent = $self->parent;
    my $qclass = $self->qclass;
    my $logger = $self->logger;
    my $errors = 0;

    return 0 unless $parent->config->should_run;

    $logger->module_stack_push();
    $logger->auto( "CONSISTENCY:BEGIN", $zone );

    my %serial_counter;
    my %digest_counter;
    my %nameservers = ();

    # fetch all nameservers, both from parent and child
    my ( $ns_parent, $ttl_parent ) = $parent->dns->get_nameservers_at_parent( $zone, $qclass );
    my ( $ns_child, $ttl_child ) = $parent->dns->get_nameservers_at_child( $zone, $qclass );

    foreach my $ns ( @$ns_parent, @$ns_child ) {
        foreach my $address ( $parent->dns->find_addresses( $ns, $qclass ) ) {
            my $ip = Net::IP->new( $address );

            if ( $ip->version == 4 and $parent->config->get( "net" )->{ipv4} ) {
                $nameservers{$address} = $address;
            }

            if ( $ip->version == 6 and $parent->config->get( "net" )->{ipv6} ) {
                $nameservers{$address} = $address;
            }
        }
    }

    foreach my $address ( keys %nameservers ) {
        my $packet = $parent->dns->query_explicit( $zone, $qclass, "SOA", $address );

        next unless ( $packet );

        foreach my $rr ( $packet->answer ) {
            next unless ( $rr->type eq "SOA" );

            my $serial = $rr->serial;

            my $digest = sha1_hex( join( ':', $rr->mname, $rr->rname, $rr->refresh, $rr->retry, $rr->expire, $rr->minimum ) );

            $logger->auto( "CONSISTENCY:SOA_SERIAL_AT_ADDRESS", $address, $serial );
            $logger->auto( "CONSISTENCY:SOA_DIGEST_AT_ADDRESS", $address, $digest );

            $serial_counter{$serial}++;
            $digest_counter{$digest}++;
        }
    }

    my $unique_serials = scalar keys %serial_counter;
    my $unique_digests = scalar keys %digest_counter;

    if ( $unique_serials > 1 ) {
        $logger->auto( "CONSISTENCY:SOA_SERIAL_DIFFERENT", $unique_serials );
    }
    else {
        $logger->auto( "CONSISTENCY:SOA_SERIAL_CONSISTENT" );
    }

    if ( $unique_digests > 1 ) {
        $logger->auto( "CONSISTENCY:SOA_DIGEST_DIFFERENT", $unique_digests );
    }
    else {
        $logger->auto( "CONSISTENCY:SOA_DIGEST_CONSISTENT" );
    }

  DONE:

    $self->test_nssets( $zone );

    $logger->auto( "CONSISTENCY:END", $zone );
    $logger->module_stack_pop();

    return 0;
}

sub test_nssets {
    my $self = shift;
    my $zone = shift;

    my $parent = $self->parent;
    my $qclass = $self->qclass;
    my $logger = $self->logger;
    my $errors = 0;

    return 0 unless $parent->config->should_run;

    my ( $parent_ns, $parent_ttl ) = $parent->dns->get_nameservers_at_parent( $zone, $qclass );
    my %sets;

    foreach my $nsname ( @$parent_ns ) {
        my @addrs = $parent->dns->find_addresses( $nsname, $qclass );
        foreach my $addr ( @addrs ) {
            my $p = $parent->dns->query_explicit( $zone, $qclass, 'NS', $addr );
            if ( $p ) {
                my @nsset = sort map { $_->string } grep { $_->type eq 'NS' } $p->answer;
                my $tmp = join( '|', @nsset );
                $logger->auto( 'CONSISTENCY:NS_SET_AT', $addr, $tmp );
                $sets{$tmp} += 1;
            }
        }
    }

    if ( keys %sets > 1 ) {
        return $logger->auto( 'CONSISTENCY:MULTIPLE_NS_SETS', $zone );
    }
    else {
        return $logger->auto( 'CONSISTENCY:NS_SETS_OK', $zone );
    }
}

1;

__END__


=head1 NAME

DNSCheck::Test::Consistency - Test zone consistency

=head1 DESCRIPTION

Test zone consistency. The following tests are made:

=over 4

=item *
The serial number of the zone must be the same at all listed name servers.

=back

=head1 METHODS

=over

=item ->test($zonename)

Check that the SOA records retrieved from all nameservers for the zone contain
the same information (that is, the same serial number and the same timeout
values).

=back

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>

=cut
