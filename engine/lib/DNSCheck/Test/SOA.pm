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

package DNSCheck::Test::SOA;

require 5.010001;
use warnings;
use strict;
use utf8;
use version;

use base 'DNSCheck::Test::Common';

use Net::IP 1.25 qw(ip_get_version);
use Net::DNS;

######################################################################

###
### Remove "helpful" behaviour added in Net::DNS 0.69
###

BEGIN {
    if (version->parse($Net::DNS::VERSION) > version->parse(0.68)) {
        require Net::DNS::Mailbox;
        no warnings 'redefine';
        *Net::DNS::Mailbox::address = sub {
            return join('.', $_[0]->label);
        };
    }
}

######################################################################

sub test {
    my $self = shift;
    my $zone = shift;

    return 0 unless $self->parent->config->should_run;

    my $logger = $self->parent->logger;

    $logger->module_stack_push();
    $logger->auto( "SOA:BEGIN", $zone );

    my ( $errors, $packet ) = $self->test_soa_existence( $zone );

    my $soa;
    if ( defined( $packet ) ) {
        $soa = ( $packet->answer )[0];
    }

    if ( defined( $soa ) ) {
        $errors += $self->test_soa_mname( $soa, $zone );
        $errors += $self->test_soa_rname( $soa, $zone );
        $errors += $self->test_soa_values( $soa, $zone );
    }

    $logger->auto( "SOA:END", $zone );
    $logger->module_stack_pop();

    return $errors;
}

################################################################
# Utility function(s)
################################################################

sub mname_is_ns {
    my ( $soa, $logger, @ns ) = @_;

    foreach my $rr ( @ns ) {
        if ( $rr->type eq 'CNAME' ) {
            $logger->auto( 'SOA:MNAME_IS_CNAME', $rr->name, $rr->cname );
        }
        elsif ( lc( $rr->nsdname ) eq lc( $soa->mname ) ) {
            return 1;
        }
    }

    return 0;
}

################################################################
# Tests
################################################################

sub test_soa_existence {
    my $self = shift;
    my $zone = shift;

    return ( 0, undef ) unless $self->parent->config->should_run;

    my $packet = $self->parent->dns->query_child( $zone, $zone, $self->qclass, "SOA" );

    my $errors = 0;

    # REQUIRE: SOA record must exist

    # Shouldn't this check that the returned SOA record actually is for the
    # requested zone? As it's written now, any SOA record at all will make the
    # test pass. /Calle
    if (   $packet
        && ( scalar( $packet->answer ) > 0 )
        && ( ( $packet->answer )[0]->type eq "SOA" ) )
    {
        $self->logger->auto( "SOA:FOUND", $zone );
    }
    else {
        $errors += $self->logger->auto( "SOA:NOT_FOUND", $zone );
        return ( $errors, undef );
    }

    # REQUIRE: only ONE SOA record may exist
    unless ( scalar( $packet->answer ) == 1 ) {
        $errors += $self->logger->auto( "SOA:MULTIPLE_SOA", $zone );
    }

    return ( $errors, $packet );
}

sub test_soa_mname {
    my $self = shift;
    my $soa  = shift;
    my $zone = shift;

    my $parent = $self->parent;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    my $errors = 0;

    # REQUIRE: SOA MNAME must exist as a valid hostname
    if ( $parent->host->test( $soa->mname ) > 0 ) {
        $errors += $logger->auto( "SOA:MNAME_ERROR", $zone, $soa->mname );
    }
    else {
        $logger->auto( "SOA:MNAME_VALID", $zone, $soa->mname );
    }

    my $packet;
    $packet = $parent->dns->query_resolver( $zone, $self->qclass, "NS" );

    unless ( $packet && scalar( $packet->answer ) ) {
        $errors += $logger->auto( "SOA:NS_NOT_FOUND", $zone );
        return $errors;
    }

    # REQUIRE: SOA MNAME may not be in the list of nameservers
    unless ( mname_is_ns( $soa, $logger, $packet->answer ) ) {
        $logger->auto( "SOA:MNAME_STEALTH", $zone, $soa->mname );
    }
    else {
        $logger->auto( "SOA:MNAME_PUBLIC", $zone, $soa->mname );
    }

    # REQUIRE: SOA MNAME may be unreachable
    # REQUIRE: SOA MNAME must be authoritative
    # FIXME: discuss how to handle timeouts
    my @addresses = $parent->dns->find_addresses( $soa->mname, $soa->class );
    foreach my $address ( @addresses ) {

        if ( ip_get_version( $address ) == 4
            && !$parent->config->get( 'net' )->{ipv4} )
        {
            $logger->auto( "SOA:SKIPPED_IPV4", $address );
            next;
        }

        if ( ip_get_version( $address ) == 6
            && !$parent->config->get( 'net' )->{ipv6} )
        {
            $logger->auto( "SOA:SKIPPED_IPV6", $address );
            next;
        }

        my $error = $parent->dns->address_is_authoritative( $address, $soa->name, $soa->class );

        if ( $error == 0 ) {
            $logger->auto( "SOA:MNAME_IS_AUTH", $zone, $soa->mname );
        }
        else {
            $logger->auto( "SOA:MNAME_NOT_AUTH", $zone, $soa->mname );
        }
    }
    return $errors;
}

sub test_soa_rname {
    my $self = shift;
    my $soa  = shift;
    my $zone = shift;

    my $errors = 0;

    my $parent = $self->parent;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    # REQUIRE: SOA RNAME must have a valid syntax (@ vs .)
    # REQUIRE: SOA RNAME address should be deliverable
    if ( $soa->rname =~ /^(.+?)(?<!\\)\.(.+)$/ ) {
        my $mailaddr = $soa->rname;

        $mailaddr =~ s/(?<!\\)\./@/;      # Replace unescaped dot with at-sign
        $mailaddr =~ s/\\\././g;          # De-escape escaped dots.

        if ( $parent->mail->test( $mailaddr, $zone ) ) {
            $logger->auto( "SOA:RNAME_UNDELIVERABLE", $zone, $soa->rname, $mailaddr );
        }
        else {
            $logger->auto( "SOA:RNAME_DELIVERABLE", $zone, $soa->rname, $mailaddr );
        }

    }
    else {
        $errors += $logger->auto( "SOA:RNAME_SYNTAX", $zone, $soa->rname );
    }

    return $errors;
}

sub test_soa_values {
    my $self = shift;
    my $soa  = shift;
    my $zone = shift;

    my $errors = 0;

    my $parent = $self->parent;
    my $logger = $self->logger;

    return 0 unless $parent->config->should_run;

    my $params = $parent->config->get( "params" );

    # REQUIRE: SOA TTL advistory, min 1 hour
    my $min_soa_ttl = $params->{"SOA:MIN_TTL"};
    if ( $soa->ttl < $min_soa_ttl ) {
        $logger->auto( "SOA:TTL_SMALL", $zone, $soa->ttl, $min_soa_ttl );
    }
    else {
        $logger->auto( "SOA:TTL_OK", $zone, $soa->ttl, $min_soa_ttl );
    }

    # REQUIRE: SOA 'refresh' at least 4 hours
    my $min_soa_refresh = $params->{"SOA:MIN_REFRESH"};
    if ( $soa->refresh < $min_soa_refresh ) {
        $logger->auto( "SOA:REFRESH_SMALL", $zone, $soa->refresh, $min_soa_refresh );
    }
    else {
        $logger->auto( "SOA:REFRESH_OK", $zone, $soa->refresh, $min_soa_refresh );
    }

    # REQUIRE: SOA 'retry' lower than 'refresh'
    unless ( $soa->retry < $soa->refresh ) {
        $logger->auto( "SOA:RETRY_VS_REFRESH", $zone, $soa->refresh, $soa->retry );
    }

    # REQUIRE: SOA 'retry' at least 1 hour
    my $min_soa_retry = $params->{"SOA:MIN_RETRY"};
    if ( $soa->retry < $min_soa_retry ) {
        $logger->auto( "SOA:RETRY_SMALL", $zone, $soa->retry, $min_soa_retry );
    }
    else {
        $logger->auto( "SOA:RETRY_OK", $zone, $soa->retry, $min_soa_retry );
    }

    # REQUIRE: SOA 'expire' at least 7 days
    my $min_soa_expire = $params->{"SOA:MIN_EXPIRE"};
    if ( $soa->expire < $min_soa_expire ) {
        $logger->auto( "SOA:EXPIRE_SMALL", $zone, $soa->expire, $min_soa_expire );
    }
    else {
        $logger->auto( "SOA:EXPIRE_OK", $zone, $soa->expire, $min_soa_expire );
    }

    # REQUIRE: SOA 'expire' at least 7 times 'refresh'
    if ( $soa->expire < $soa->refresh * $params->{"SOA:EXPIRE_VS_REFRESH"} ) {
        $logger->auto( "SOA:EXPIRE_VS_REFRESH", $zone );
    }

    # REQUIRE: SOA 'minimum' less than 1 day
    my $max_soa_minimum = $params->{"SOA:MAX_MINIMUM"};
    my $min_soa_minimum = $params->{"SOA:MIN_MINIMUM"};
    if ( $soa->minimum > $max_soa_minimum ) {
        $logger->auto( "SOA:MINIMUM_LARGE", $zone, $soa->minimum, $max_soa_minimum );
    }
    elsif ( $soa->minimum < $min_soa_minimum ) {
        $logger->auto( "SOA:MINIMUM_SMALL", $zone, $soa->minimum, $min_soa_minimum );
    }
    else {
        $logger->auto( "SOA:MINIMUM_OK", $zone, $soa->minimum, $min_soa_minimum, $max_soa_minimum );
    }

    # RFC 2136 says serial should not be zero
    if ( $soa->serial == 0 ) {
        $logger->auto( 'SOA:SERIAL_IS_ZERO', $zone );
    }

    return $errors;
}

1;

__END__


=head1 NAME

DNSCheck::Test::SOA - Test SOA record

=head1 DESCRIPTION

Test the zone SOA record. The following tests are made:

=over 4

=item *
The SOA record must exist.

=item *
Only ONE SOA record may exist.

=item *
SOA MNAME must exist as a valid hostname.

=item *
SOA MNAME does not have to be in the list of nameservers.

=item *
SOA MNAME does not have to be reachable.

=item *
SOA MNAME must be authoritative for the zone.

=item *
SOA RNAME must have a valid syntax .

=item *
SOA RNAME address should be deliverable.

=item *
SOA TTL should be at least 1 hour.

=item *
SOA 'refresh' should be at least 4 hours.

=item *
SOA 'retry' should be lower than SOA 'refresh'.

=item *
SOA 'retry' shoule be at least 1 hour.

=item *
SOA 'expire' should be at least 7 days.

=item *
SOA 'expire' should be at least 7 times SOA 'refresh'.

=item *
SOA 'minimum' should be less than 1 day.

=back

=head1 METHODS

=over

=item ->test($zonename)

Runs all the tests specified above.

=item ->test_soa_existence($zonename)

Tests that one and only one SOA record exists.

=item ->test_soa_mname($soapacket, $zonename)

Runs the MNAME-related tests.

C<$soapacket> must be a L<Net::DNS::RR::SOA> object suitably filled in.

=item ->test_soa_rname($soapacket, $zonename)

Runs the RNAME-related tests.

=item ->test_soa_values($soapacket, $zonename)

Runs the tests checking the values in the given SOA record.

=item ->mname_is_ns(@nslist)

Internal utility method.

=back

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>, L<DNSCheck::Test::Host>,
L<DNSCheck::Test::Mail>

=cut
