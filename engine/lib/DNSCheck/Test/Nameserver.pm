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

package DNSCheck::Test::Nameserver;

require 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';

use Net::IP 1.25 qw[ip_get_version];

######################################################################

sub test {
    my $self       = shift;
    my $parent     = $self->parent;
    my $zone       = shift // $self->zone;
    my $nameserver = shift // $self->ns;

    return 0 unless $parent->config->should_run;

    my $logger = $parent->logger;
    my $errors = 0;

    $self->zone( $zone );
    $self->ns( $nameserver );

    my $packet;

    $logger->module_stack_push();
    $logger->auto( "NAMESERVER:BEGIN", $nameserver );

    # REQUIRE: Nameserver must be a valid hostname
    if ( $parent->host->test( $nameserver ) ) {
        $errors += $logger->auto( "NAMESERVER:HOST_ERROR", $nameserver );
        goto DONE;
    }

    # Does this name encode a DNSCurve public key?
    if ($nameserver =~ m|^uz5[0123456789bcdfghjklmnpqrstuvwxyz]{51}\.|i) {
        $logger->auto( "NAMESERVER:DNSCURVE", $nameserver);
    }

    my @addresses = $parent->dns->find_addresses( $nameserver, $self->qclass );

    $errors += $self->_test_ip( @addresses );

  DONE:
    $logger->auto( "NAMESERVER:END", $nameserver );
    $logger->module_stack_pop();

    return $errors;
}

sub test_by_ip {
    my $self       = shift;
    my $parent     = $self->parent;
    my $zone       = shift;
    my $nameserver = shift;

    my $qclass = $self->qclass;
    my $logger = $parent->logger;
    my $errors = 0;

    $self->zone( $zone );
    $self->ns( $nameserver );

    my $packet;

    $logger->module_stack_push();
    $logger->auto( "NAMESERVER:BEGIN", $nameserver );

    # This only works because we know $errors is zero here.
    if ( $errors += $parent->address->test( $nameserver ) ) {
        goto DONE;
    }

    $errors += $self->_test_ip( $nameserver );

  DONE:
    $logger->auto( "NAMESERVER:END", $nameserver );
    $logger->module_stack_pop();

    return $errors;
}

sub _test_ip {
    my ( $self, @addresses ) = @_;

    my $parent     = $self->parent;
    my $zone       = $self->zone;
    my $nameserver = $self->ns;
    my $qclass     = $parent->config->get( "dns" )->{class};
    my $logger     = $parent->logger;
    my $errors     = 0;

    my $packet;

  ADDRESS: foreach my $address ( @addresses ) {

        my $skip_udp = 0;
        my $skip_tcp = 0;

        if ( ip_get_version( $address ) == 4
            && !$parent->config->get( "net" )->{ipv4} )
        {
            $logger->auto( "NAMESERVER:SKIPPED_IPV4", $address );
            next ADDRESS;
        }

        if ( ip_get_version( $address ) == 6
            && !$parent->config->get( "net" )->{ipv6} )
        {
            $logger->auto( "NAMESERVER:SKIPPED_IPV6", $address );
            next ADDRESS;
        }

        my $tmp_udp = $self->ns_udp( $address );
        $errors += $tmp_udp;
        $skip_udp = 1 if $tmp_udp > 0;

        my $tmp_tcp = $self->ns_tcp( $address );
        $errors += $tmp_tcp;
        $skip_tcp = 1 if $tmp_tcp > 0;

        # No point in trying to test the server if it's not responding at all
        if ( $tmp_udp and $tmp_tcp ) {
            next ADDRESS;
        }

        $errors += $self->ns_recursive( $address );
        $errors += $self->same_source( $address );

        my $tmp = $self->ns_authoritative( $address );
        $errors += $tmp;
        next ADDRESS if $tmp > 0;

        # REQUIRE: Nameserver may provide AXFR
        if ( $skip_tcp ) {
            $logger->auto( "NAMESERVER:AXFR_SKIP", $nameserver, $address, $zone );
        }
        else {
            $errors += $self->ns_axfr( $address );
        }

        # Check for possible identification
        unless ( $skip_tcp || $skip_udp ) {
            $logger->auto( "NAMESERVER:CHECKING_LEGACY_ID", $nameserver, $address );
            $self->ns_check_id( $address );
        }
        else {
            $logger->auto( "NAMESERVER:LEGACY_ID_SKIP", $nameserver, $address );
        }

        $logger->auto("NAMESERVER:CHECKING_NSID", $nameserver, $address);
        my $nsid = $parent->dns->query_nsid($address, $zone, $qclass, "SOA");
        if (defined($nsid)) {
            # $nsid is a array ref, with two values
            $logger->auto("NAMESERVER:NSID", $nameserver, $address, $nsid);
        }
    }

    return $errors;
}

sub zone {
    my $self = shift;
    my $zone = shift;

    if ( defined( $zone ) ) {
        $self->{zone} = $zone;
    }

    return $self->{zone};
}

sub ns {
    my $self = shift;
    my $ns   = shift;

    if ( defined( $ns ) ) {
        $self->{nameserver} = $ns;
    }

    return $self->{nameserver};
}

sub ns_check_id {
    my $self       = shift;
    my $address    = shift;
    my $nameserver = shift // $self->ns;

    return 0 unless $self->parent->config->should_run;

    my $logger = $self->logger;

    my @domains = ( "hostname.bind", "version.bind", "id.server", "version.server" );

    my $packet;

    for my $domain ( @domains ) {
        $packet = $self->parent->dns->query_explicit( $domain, "CH", "TXT", $address );

        if ( $packet ) {
            foreach my $rr ( $packet->answer ) {
                next unless ( ( $rr->type eq "TXT" ) && $rr->txtdata );

                $logger->auto( "NAMESERVER:LEGACY_ID", $nameserver, $address, $domain, $rr->txtdata );
            }
        }
    }

    return;
}

################################################################
# Individual tests
################################################################

sub ns_recursive {
    my $self       = shift;
    my $address    = shift;
    my $nameserver = shift // $self->ns;

    return 0 unless $self->parent->config->should_run;

    # REQUIRE: Nameserver should not be recursive
    $self->logger->auto( "NAMESERVER:CHECKING_RECURSION", $nameserver, $address );
    if ( $self->parent->dns->address_is_recursive( $address, $self->qclass ) ) {
        return $self->logger->auto( "NAMESERVER:RECURSIVE", $nameserver, $address );
    }
    else {
        return $self->logger->auto( "NAMESERVER:NOT_RECURSIVE", $nameserver, $address );
    }
}

sub ns_authoritative {
    my $self       = shift;
    my $address    = shift;
    my $nameserver = shift // $self->ns;
    my $zone       = shift // $self->zone;

    return 0 unless $self->parent->config->should_run;

    # REQUIRE: Nameserver must be authoritative for the zone
    #          [IIS.KVSE.001.01/r3,IIS.KVSE.001.01/r6]
    $self->logger->auto( "NAMESERVER:CHECKING_AUTH", $nameserver, $address );
    if (
        $self->parent->dns->address_is_authoritative( $address, $zone, $self->qclass )
        or
        $self->parent->dns->address_is_authoritative_tcp( $address, $zone, $self->qclass )
    ) {
        return $self->logger->auto( "NAMESERVER:NOT_AUTH", $nameserver, $address, $zone );
    }
    else {
        return $self->logger->auto( "NAMESERVER:AUTH", $nameserver, $address, $zone );
    }
}

sub ns_udp {
    my $self       = shift;
    my $address    = shift;
    my $nameserver = shift // $self->ns;
    my $zone       = shift // $self->zone;

    return 0 unless $self->parent->config->should_run;

    $self->logger->auto( "NAMESERVER:TESTING_UDP", $nameserver, $address );
    my $packet = $self->parent->dns->query_explicit( $zone, $self->qclass, "SOA", $address, { transport => "udp", aaonly => 0 } );
    if ( $packet ) {
        return $self->logger->auto( "NAMESERVER:UDP_OK", $nameserver, $address, $zone );
    }
    else {
        return $self->logger->auto( "NAMESERVER:NO_UDP", $nameserver, $address, $zone );
    }
}

sub ns_tcp {
    my $self       = shift;
    my $address    = shift;
    my $nameserver = shift // $self->ns;
    my $zone       = shift // $self->zone;

    return 0 unless $self->parent->config->should_run;

    $self->logger->auto( "NAMESERVER:TESTING_TCP", $nameserver, $address );
    my $packet = $self->parent->dns->query_explicit( $zone, $self->qclass, "SOA", $address, { transport => "tcp", aaonly => 0 } );
    if ( $packet ) {
        return $self->logger->auto( "NAMESERVER:TCP_OK", $nameserver, $address, $zone );
    }
    else {
        return $self->logger->auto( "NAMESERVER:NO_TCP", $nameserver, $address, $zone );
    }
}

sub ns_axfr {
    my $self       = shift;
    my $address    = shift;
    my $nameserver = shift // $self->ns;
    my $zone       = shift // $self->zone;

    return 0 unless $self->parent->config->should_run;

    $self->logger->auto( "NAMESERVER:TESTING_AXFR", $nameserver, $address );
    if ( $self->parent->dns->check_axfr( $address, $zone, $self->qclass ) ) {
        return $self->logger->auto( "NAMESERVER:AXFR_OPEN", $nameserver, $address, $zone );
    }
    else {
        return $self->logger->auto( "NAMESERVER:AXFR_CLOSED", $nameserver, $address, $zone );
    }
}

sub same_source {
    my $self    = shift;
    my $address = shift;
    my $zone    = shift // $self->zone;

    return 0 unless $self->parent->config->should_run;

    my $p = $self->parent->dns->query_explicit( $zone, 'SOA', 'IN', $address );
    return 0 unless $p;

    my $to = Net::IP->new( $address );
    return 0 unless $to;
    $to = $to->ip;

    my $from = Net::IP->new( $p->answerfrom );
    return 0 unless $from;
    $from = $from->ip;

    if ( $to eq $from ) {
        return $self->parent->logger->auto( 'NAMESERVER:SAME_SOURCE', $address );
    }
    else {
        return $self->parent->logger->auto( 'NAMESERVER:NOT_SAME_SOURCE', $address );
    }
}

1;

__END__


=head1 NAME

DNSCheck::Test::Nameserver - Test a nameserver

=head1 DESCRIPTION

Test a single name server for a specific zone. The following tests are done:

=over 4

=item *
The nameserver must be a valid hostname (according to L<DNSCheck::Test::Host>).

=item *
The nameserver should not be recursive.

=item *
The nameserver must be authoritative for the zone.

=item *
The SOA record for the zone must be fetchable over both UDP and TCP.

=item *
The nameserver may provide AXFR for the zone.

=back

=head1 METHODS

=over

=item ->new($parent, $zone, $nameserver)

Create a new test object, and optionally set the zone and nameserver name that
will be tested. If those two are set, the values will be used as defaults for
many other methods.

=item ->test($zone, $nameserver);

Perform the default set of tests for a nameserver in a delegated domain. Uses
the defaults set in L<new()>, if any. Returns the number of problems found at
level ERROR and CRITICAL (as well as detiled log info in the parent's logger
object as usual).

For this test, a lookup on the nameserver name will be made and all tests run
on all addresses found (obeying global settings for use of IPv4 and IPv6, of
course).

=item ->test_by_ip($zone, $ip)

Run as many tests as make sense on the nameserver at the given IP address.

=item ->zone($zone)

Get or set the default zone for this object.

=item ->ns($name)

Get or set the default nameserver name for this object.

=item ->ns_check_id($ip, [$name])

Run the version-fetching test for the specified server.

=item ->ns_recursive($ip, [$name])

Test if the specified server is recursive. As all tests here, returns the
number of problems on levels ERROR and CRITICAL found, and populates the
logger object.

=item ->ns_authoritative($ip, [$name, $zone])

Test if the specified server is authoritative for the given zone (nameserver
name is only used for logging).

=item ->ns_udp($ip, [$name, $zone])

Test if the given server can be queried via UDP.

=item ->ns_tcp($ip, [$name, $zone])

Test if the given server can be queried via TCP.

=item ->ns_axfr($ip, [$name, $zone])

Test if the given server allows transfer of the given zone.

=item ->same_source($address)

Checks that queries sent to a given address gets responses coming from the same address.

=back

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>, L<DNSCheck::Test::Host>

=cut
