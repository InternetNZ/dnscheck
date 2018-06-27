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

package DNSCheck::Test::Connectivity;

use 5.010001;
use warnings;
use strict;
use utf8;
use Carp;
use Net::IP;
use List::Util qw[max];

use base 'DNSCheck::Test::Common';

######################################################################

sub test {
    my $self = shift;
    my $zone = shift;

    my $parent = $self->parent;
    my $qclass = $self->qclass;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    $logger->module_stack_push();
    $logger->auto( "CONNECTIVITY:BEGIN", $zone );

    my $errors = $self->test_v4( $zone ) + $self->test_v6( $zone );

    $logger->auto( "CONNECTIVITY:END", $zone );
    $logger->module_stack_pop();

    return $errors;
}

sub test_v4 {
    my $self = shift;
    my $zone = shift;

    my $parent = $self->parent;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    my $errors = $self->test_as_diversity( $zone, 4 );

    # REQUIRE: Domain name servers should live in more than one AS
    if ( $errors == 1 ) {
        return $logger->auto( "CONNECTIVITY:TOO_FEW_ASN" );
    }
    else {
        return $logger->auto( "CONNECTIVITY:ASN_COUNT_OK" );
    }
}

sub test_v6 {
    my $self = shift;
    my $zone = shift;

    my $parent = $self->parent;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    my $errors = $self->test_as_diversity( $zone, 6 );

    # REQUIRE: Domain name servers should live in more than one AS
    if ( $errors == 1 ) {
        return $logger->auto( "CONNECTIVITY:V6_TOO_FEW_ASN" );
    }
    else {
        return $logger->auto( "CONNECTIVITY:V6_ASN_COUNT_OK" );
    }
}

sub test_as_diversity {
    my $self      = shift;
    my $zone      = shift;
    my $ipversion = shift // 4;

    my $parent = $self->parent;
    my $qclass = $self->qclass;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    my @nameservers = ();

    # Fetch nameservers
    my $ip;
    if ( $ipversion == 4 ) {
        $ip = $parent->dns->get_nameservers_ipv4( $zone, $qclass );
    }
    elsif ( $ipversion == 6 ) {
        $ip = $parent->dns->get_nameservers_ipv6( $zone, $qclass );
    }
    else {
        croak "Don't know how to handle IP version $ipversion";
    }

    return 1 if !$ip;
    my @asdata = $self->_clean_list( map { $parent->asn->asdata( $_ ) } @$ip );

    my %count;
    my $total = 0;

    foreach my $item ( @asdata ) {
        foreach my $as ( @{ $item->[0] } ) {
            $count{$as} += 1;
        }
        $total += 1;
    }

    # Reserved ranges come from http://www.iana.org/assignments/as-numbers/as-numbers.xml
    foreach my $asn (keys %count) {
        if ( $asn == 0 or ($asn >= 64000 and $asn <= 131071) or ($asn >= 4200000000 and $asn <= 4294967295) ) {
            $logger->auto( 'CONNECTIVITY:RESERVED_AS', $zone, $asn);
        }
    }

    if ( $total <= 1 or max( values %count ) == $total ) {
        return 1;    # Error, one AS announced for all prefixes
    }
    else {
        return 0;
    }
}

sub _clean_list {
    my ($self, @args) = @_;
    my ( $head, @tail ) = sort { $a->[1]->prefixlen <=> $b->[1]->prefixlen } @args;
    my @tmp = ();

    return unless $head;

    foreach my $item ( @tail ) {
        my $res = $head->[1]->overlaps( $item->[1] );
        if ( $res == $IP_NO_OVERLAP ) {
            push @tmp, $item;
        }
        elsif ( $res == $IP_IDENTICAL ) {

            # Skip this $item
        }
        elsif ( $res == $IP_A_IN_B_OVERLAP ) {
            croak "Cannot happen, longer prefix encloses shorter";
        }
        elsif ( $res == $IP_B_IN_A_OVERLAP ) {
            # Skip, $item is enclosed by $head
            $self->parent->logger->auto('ASN:PREFIX_SKIPPED', $item->[1]->prefix);
        }
        elsif ( $res == $IP_PARTIAL_OVERLAP ) {
            croak "Partial";
        }
        else {
            croak "Error";
        }
    }

    return ( $head, $self->_clean_list( @tmp ) );
}

1;

__END__


=head1 NAME

DNSCheck::Test::Connectivity - Test zone connectivity

=head1 DESCRIPTION

Test connectivity for a zone's nameservers. The following tests are made:

=over 4

=item *
A name server should not be announced by more than one AS.

=item *
A name server must be announced.

=item *
Domain name servers should live in more than one AS.

=item *
Messages are logged if any ASs on IANAs reserved list are found.

=back

=head1 METHODS

=over

=item ->test($zonename);

=item ->test_v4($zonename)

Test specifically for IPv4.

=item ->test_v6($zonename)

Test specifically for IPv6.

=item ->test_as_diversity($zone, $ipversion)

This is a method that implements the parts of AS diversity testing that is largely common between the IP protocol versions.

=back

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>

=cut
