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

package DNSCheck::Test::Delegation;

use 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';
use Net::IP qw[:PROC];
use Net::DNS::Packet;
use Net::DNS::RR;

######################################################################

sub test {
    my $self    = shift;
    my $zone    = shift;
    my $history = shift;

    my $parent = $self->parent;

    return ( 0, 0 ) unless $parent->config->should_run;

    if ( !defined( $history ) && $parent->dbh ) {
        $history =
          $parent->dbh->selectcol_arrayref( 'SELECT DISTINCT nameserver FROM delegation_history WHERE domain=?',
            undef, $zone );
    }

    my $qclass = $self->qclass;
    my $logger = $parent->logger;
    my $errors = 0;

    my $testable = undef;

    $logger->module_stack_push();
    $logger->auto( "DELEGATION:BEGIN", $zone );

    if ( $parent->undelegated_test
        and scalar( $parent->resolver->faked_zones ) == 0 )
    {
        $errors = $logger->auto( 'DELEGATION:BROKEN_UNDELEGATED', $zone );
        $testable = 0;
        goto DONE;
    }

    my $packet;

    ( $errors, $testable ) = $self->ns_parent_child_matching( $zone );

    if ( !$testable ) {
        my $p_a   = $self->parent->dns->query_resolver( $zone,          'IN', 'A' );
        my $p_www = $self->parent->dns->query_resolver( 'www.' . $zone, 'IN', 'A' );
        if ( ( $p_a and scalar( $p_a->answer ) > 0 ) or ( $p_www and scalar( $p_www->answer ) > 0 ) ) {
            $self->logger->auto( 'DELEGATION:BROKEN_BUT_FUNCTIONAL', $zone );
        }
    }

    goto DONE unless $testable;

    $errors += $self->enough_nameservers( $zone );
    $errors += $self->consistent_glue( $zone );
    $errors += $self->in_zone_ns_glue( $zone );
    $errors += $self->cname_as_ns( $zone );
    $errors += $self->referral_size( $zone );

    # Test old namservers if we have history
    if ( $history ) {
        $self->check_history( $zone, $history );
    }

  DONE:
    $logger->auto( "DELEGATION:END", $zone );
    $logger->module_stack_pop();

    return ( $errors, $testable );
}

################################################################
# Utility functions
################################################################

sub _get_glue {
    my $parent = shift;
    my $zone   = shift;

    my $qclass = $parent->config->get( "dns" )->{class};
    my $logger = $parent->logger;

    my @glue = ();

    my ( $ns, $ttl ) = $parent->dns->get_nameservers_at_parent( $zone, $qclass );
    @$ns = () unless $ns->[0];

    foreach my $nameserver ( @$ns ) {
        my $ipv4 = $parent->dns->query_parent( $zone, $nameserver, $qclass, "A" );

        if ( $ipv4 ) {
            my @sorted_ipv4 =
              sort { $a->name cmp $b->name } ( $ipv4->answer, $ipv4->additional );

            foreach my $rr ( @sorted_ipv4 ) {
                if ( $rr->type eq "A" and $rr->name eq $nameserver ) {
                    $logger->auto( "DELEGATION:GLUE_FOUND_AT_PARENT", $zone, $rr->name, $rr->address );
                    push @glue, $rr;
                }
            }
        }

        my $ipv6 = $parent->dns->query_parent( $zone, $nameserver, $qclass, "AAAA" );

        if ( $ipv6 ) {
            my @sorted_ipv6 =
              sort { $a->name cmp $b->name } ( $ipv6->answer, $ipv6->additional );

            foreach my $rr ( @sorted_ipv6 ) {
                if ( $rr->type eq "AAAA" and $rr->name eq $nameserver ) {
                    $logger->auto( "DELEGATION:GLUE_FOUND_AT_PARENT", $zone, $rr->name, $rr->address );
                    push @glue, $rr;
                }
            }
        }
    }

    return @glue;
}

################################################################
# Single tests
################################################################

sub consistent_glue {
    my ($self, $zone) = @_;

    my $parent = $self->parent;
    my $logger = $self->logger;
    my $qclass = $self->qclass;

    return 0 unless $parent->config->should_run;

    my $errors = 0;
    $zone =~ s/\.$//;

    # REQUIRE: check for inconsistent glue
    my @glue = _get_glue( $parent, $zone );

    foreach my $g ( @glue ) {
        $logger->auto( "DELEGATION:MATCHING_GLUE", $g->name, $g->address );

        # make sure we only check in-zone-glue
        my $gname = $g->name;
        $gname =~ s/\.$//;
        unless ( $g->name =~ /(^|\.)$zone$/i ) {
            $logger->auto( "DELEGATION:GLUE_SKIPPED", $g->name, "out-of-zone", $zone );
            next;
        }

        my $c = $parent->dns->query_child( $zone, $g->name, $g->class, $g->type );
        my $chain = {};

      RETEST:
        if ( $c and $c->header->rcode eq "NOERROR" ) {
            ## got NOERROR, might be good or bad - dunno yet

            if ( scalar( $c->answer ) > 0 ) {
                ## got positive answer back, let's see if this makes any sense

                # Not AUTH. Bad.
                if ( $c and not $c->header->aa ) {
                    $errors += $logger->auto( 'DELEGATION:CHILD_GLUE_NOT_AUTH', $zone, $g->name );
                    next;
                }

                my $found = 0;
                foreach my $rr ( $c->answer ) {
                    if (    lc( $rr->name ) eq lc( $g->name )
                        and $rr->class eq $g->class
                        and $rr->type eq $g->type
                        and $rr->address eq $g->address )
                    {
                        $logger->auto( "DELEGATION:GLUE_FOUND_AT_CHILD", $zone, $g->name, $g->address );
                        $found++;
                    }
                    elsif ( $rr->type eq 'CNAME' ) {
                        $errors += $logger->auto( 'DELEGATION:CHILD_GLUE_CNAME', $zone, $g->name );
                    }
                    elsif ( $rr->type eq 'DNAME' ) {
                        $errors += $logger->auto( 'DELEGATION:CHILD_GLUE_DNAME', $zone, $g->name );
                    }
                }

                if ( not $found ) {
                    $errors += $logger->auto( "DELEGATION:INCONSISTENT_GLUE",
                        $g->name, join( ',', map { $_->address } grep { $_->type eq $g->type } $c->answer ) );
                }
            }
            elsif ( scalar( $c->authority ) > 0 ) {
                ## got referer or nothing, authority section needs study

                my $soa = undef;
                my $ns  = undef;

                foreach my $rr ( $c->authority ) {
                    $soa = $rr if ( $rr->type eq "SOA" );
                    $ns  = $rr if ( $rr->type eq "NS" );
                }

                ## got NOERROR and NS in authority section -> referer
                if ( $ns ) {
                    $c = $self->follow_referral( $c, $g->name, $g->class, $g->type, $chain );
                    if ( $c ) {
                        $logger->auto( 'DELEGATION:GLUE_REFERRAL_FOLLOWED', $g->name );
                        goto RETEST;
                    }
                    else {
                        $errors += $logger->auto( 'DELEGATION:GLUE_BROKEN_REFERRAL', $g->name );
                        next;
                    }
                }

                ## got NOERROR and SOA in authority section -> not found
                if ( $soa ) {
                    $logger->auto( "DELEGATION:GLUE_MISSING_AT_CHILD", $g->name );
                    next;
                }
            }
        }
        elsif ( $c and $c->header->rcode eq "REFUSED" ) {
            ## got REFUSED, probably not authoritative
            $logger->auto( "DELEGATION:GLUE_ERROR_AT_CHILD", $g->name, "refused" );
            next;
        }
        elsif ( $c and $c->header->rcode eq "SERVFAIL" ) {
            ## got SERVFAIL, most likely not authoritative
            $logger->auto( "DELEGATION:GLUE_ERROR_AT_CHILD", $g->name, "servfail" );
            next;
        }
        else {
            ## got something else, let's blame the user...
            $errors += $logger->auto( "DELEGATION:GLUE_ERROR_AT_CHILD", $g->name, 'unknown problem' );
            next;
        }
    }

    return $errors;
}

sub ns_parent_child_matching {
    my $self = shift;
    my $zone = shift;

    my $errors = 0;
    my $testable;

    return ( 0, 0 ) unless $self->parent->config->should_run;

    my ( $ns_at_parent, $ttl_at_parent ) = $self->parent->dns->get_nameservers_at_parent( $zone, $self->qclass );
    @$ns_at_parent = () unless $ns_at_parent->[0];
    if ( scalar @$ns_at_parent ) {
        $self->logger->auto( "DELEGATION:NS_AT_PARENT", join( ",", @$ns_at_parent ), $ttl_at_parent );
        $testable = 1;
    }
    else {
        $errors += $self->logger->auto( "DELEGATION:NOT_FOUND_AT_PARENT" );
        $testable = 0;
    }

    return ( $errors, $testable ) unless $testable;

    my ( $ns_at_child, $ttl_at_child ) = $self->parent->dns->get_nameservers_at_child( $zone, $self->qclass );
    @$ns_at_child = () unless $ns_at_child->[0];
    if ( scalar @$ns_at_child ) {
        $self->logger->auto( "DELEGATION:NS_AT_CHILD", join( ",", @$ns_at_child ), $ttl_at_child );
    }
    else {
        $errors += $self->logger->auto( "DELEGATION:NOT_FOUND_AT_CHILD" );
        $testable = 0;
    }

    return ( $errors, $testable ) unless $testable;

    # REQUIRE: all NS at parent must exist at child [IIS.KVSE.001.01/r2]
    my @ns_at_both;
    foreach my $ns ( @$ns_at_parent ) {
        unless ( scalar grep { /^\Q$ns\E$/i } @$ns_at_child ) {
            $errors += $self->logger->auto( "DELEGATION:EXTRA_NS_PARENT", $ns );
        }
        else {
            push @ns_at_both, $ns;
        }
    }

    # REQUIRE: at least two (2) NS records at parent [IIS.KVSE.001.01/r1]
    # Modified to check for NS records that exist at both parent and child.
    if ( @ns_at_both == 1 ) {
        $self->logger->auto( "DELEGATION:TOO_FEW_NS", scalar @ns_at_both );
    }
    elsif ( @ns_at_both == 0 and $testable ) {
        $self->logger->auto( "DELEGATION:NO_COMMON_NS_NAMES", join( ",", @$ns_at_parent ), join( ",", @$ns_at_child ) );
    }
    elsif ( @ns_at_both > 1 ) {
        ## Everything is fine.
    }

    # REQUIRE: all NS at child may exist at parent
    foreach my $ns ( @$ns_at_child ) {
        unless ( scalar grep { /^$ns$/i } @$ns_at_parent ) {
            $self->logger->auto( "DELEGATION:EXTRA_NS_CHILD", $ns );
        }
    }

    return ( $errors, $testable );
}

sub enough_nameservers {
    my $self   = shift;
    my $zone   = shift;
    my $errors = 0;

    return 0 unless $self->parent->config->should_run;

    # REQUIRE: at least two IPv4 nameservers must be found
    my $ipv4_ns = $self->parent->dns->get_nameservers_ipv4( $zone, $self->qclass );
    if ( $ipv4_ns && scalar( @{$ipv4_ns} < 2 ) ) {
        $errors += $self->logger->auto( "DELEGATION:TOO_FEW_NS_IPV4", scalar @{$ipv4_ns} );
    }
    unless ( $ipv4_ns ) {
        $errors += $self->logger->auto( "DELEGATION:NO_NS_IPV4" );
    }

    # REQUIRE: at least two IPv6 nameservers should be found
    my $ipv6_ns = $self->parent->dns->get_nameservers_ipv6( $zone, $self->qclass );
    if ( $ipv6_ns && scalar( @{$ipv6_ns} < 2 ) ) {
        $errors += $self->logger->auto( "DELEGATION:TOO_FEW_NS_IPV6", scalar @{$ipv6_ns} );
    }
    unless ( $ipv6_ns ) {
        $errors += $self->logger->auto( "DELEGATION:NO_NS_IPV6" );
    }

    return $errors;
}

sub check_history {
    my $self     = shift;
    my $zone     = shift;
    my $previous = shift;

    my $parent = $self->parent;
    my $qclass = $self->qclass;
    my $logger = $self->logger;

    return unless $parent->config->should_run;

    my @old = ();

    my ( $ns_at_parent, $ttl_at_parent ) = $parent->dns->get_nameservers_at_parent( $zone, $qclass );
    my $current = $ns_at_parent;

    # Build a hash with all IP addresses for all current nameservers
    my %current_addresses =
      map { $_ => 1 }
      map { $parent->dns->find_addresses( $_, $qclass ) } @$current;

    # do not check current nameservers
    foreach my $ns ( @$previous ) {
        unless ( grep { /^$ns$/ } @$current ) {
            push @old, $ns;
        }
    }

    $logger->auto( "DELEGATION:NS_HISTORY", $zone, join( ",", @old ) );

    foreach my $ns ( @old ) {
        my @addresses = $parent->dns->find_addresses( $ns, $qclass );

        # FIXME: also skip current IP addresses

        foreach my $address ( @addresses ) {

            # Skip to next address if this one leads to a current server
            next if $current_addresses{$address};
            my $packet = $parent->dns->query_explicit( $zone, $qclass, "SOA", $address, { noservfail => 1 } );
            if ( $packet && $packet->header->aa ) {
                $logger->auto( "DELEGATION:STILL_AUTH", $ns, $address, $zone );
            }
        }
    }

    return;
}

sub in_zone_ns_glue {
    my ( $self, $zone ) = @_;
    my $errors = 0;

    return unless $self->parent->config->should_run;

    my %glue = map { $_->name, $_->address } _get_glue( $self->parent, $zone );
    my ( $ns_at_parent, $ttl_at_parent ) = $self->parent->dns->get_nameservers_at_parent( $zone, $self->qclass );

    foreach my $ns ( @$ns_at_parent ) {
        if ( $ns =~ /\Q$zone\E$/ and not $glue{$ns} ) {
            $errors += $self->logger->auto( "DELEGATION:INZONE_NS_WITHOUT_GLUE", $ns, $zone );
        }
    }

    return $errors;
}

sub cname_as_ns {
    my ( $self, $zone ) = @_;
    my $error = 0;

    return 0 unless $self->parent->config->should_run;

    my ( $ns, $ttl ) = $self->parent->dns->get_nameservers_at_child( $zone, $self->qclass );

    foreach my $ns ( @$ns ) {
        my $a    = $self->parent->dns->query_child( $zone, $ns, $self->qclass, 'A' );
        my $aaaa = $self->parent->dns->query_child( $zone, $ns, $self->qclass, 'AAAA' );
        my @rrs  = ();

        if ( $a ) {
            push @rrs, $a->answer;
            push @rrs, $a->authority;
        }

        if ( $aaaa ) {
            push @rrs, $aaaa->answer;
            push @rrs, $aaaa->authority;
        }

        foreach my $rr ( @rrs ) {
            next unless $rr->name eq $ns;
            if ( $rr->type eq 'CNAME' ) {
                $error += $self->logger->auto( "DELEGATION:NS_IS_CNAME", $zone, $ns );
                last;
            }
        }
    }

    return $error;
}

###
### Truncated referral test
###

sub referral_size {
    my ( $self, $zone ) = @_;

    my %data;
    my ( $ns, $ttl ) = $self->parent->dns->get_nameservers_at_child( $zone, 'IN' );
    foreach my $nsname ( @$ns ) {
        $data{$nsname} = [ $self->parent->dns->find_addresses( $nsname, 'IN' ) ];
    }

    my $min_size = $self->min_packet_length( $zone, %data );
    $self->parent->logger->auto( 'DELEGATION:MIN_REFERRAL_SIZE', $zone, $min_size );

    if ( $min_size <= 512 ) {
        return $self->parent->logger->auto( 'DELEGATION:MIN_REFERRAL_SIZE_OK', $zone );
    }
    else {
        return $self->parent->logger->auto( 'DELEGATION:MIN_REFERRAL_SIZE_TOO_BIG', $zone, $min_size );
    }
}

# Make up a name of maximum length in the given domain
sub _max_length_name_for {
    my ( $top ) = @_;
    my @chars = 'A' .. 'Z';

    my $name = '';
    $name = $top;

    $name .= '.' if $name !~ m/\.$/;

    while ( length( $name ) < 253 ) {
        my $len = 253 - length( $name );
        $len = 63 if $len > 63;
        $name = join( '', map { $chars[ rand @chars ] } 1 .. $len ) . '.' . $name;
    }

    return $name;
}

# Return the length in bytes of the smallest valid referal packet. In
# order to be valid, the packet must contain NS records for all
# nameservers. If there are any in-zone nameservers, there must be at
# least one A glue record. If any of the in-zone nameservers have IPv6
# addresses, there must also be an AAAA glue record.
sub min_packet_length {
    my ( $self, $topdomain, %data ) = @_;

    # Create a packet with an NS query for the given domain
    my $p = Net::DNS::Packet->new( _max_length_name_for( $topdomain ), 'NS', 'IN' );

    # Add NS records for all given nameservers to Authority section
    foreach my $name ( keys %data ) {
        my $rr = Net::DNS::RR->new( sprintf( '%s 3600 IN NS %s', $topdomain, $name ) );

        $p->unique_push( authority => $rr );
    }

    # Names that need glue, in order from shortest to longest
    my @candidates = sort { length( $a ) <=> length( $b ) } grep { /\Q$topdomain\E\.?$/ } keys %data;

    # Go through the names adding one A and one AAAA glue record.
    my ( $v6, $v4 );
    foreach my $name ( @candidates ) {
        foreach my $addr ( @{ $data{$name} } ) {
            my $rr;

            if ( $addr =~ /:/ ) {
                if ( !$v6 ) {
                    $rr = Net::DNS::RR->new( sprintf( '%s 3600 IN AAAA %s', $name, $addr ) );
                    $v6 = 1;
                }
            }
            else {
                if ( !$v4 ) {
                    $rr = Net::DNS::RR->new( sprintf( '%s 3600 IN A %s', $name, $addr ) );
                    $v4 = 1;
                }
            }

            $p->unique_push( additional => $rr );
        }
    }

    return length( $p->data );
}

###
### Helper method
###

sub follow_referral {
    my ( $self, $packet, $name, $class, $type, $chain) = @_;

    my %authority;
    $authority{$_->name}{$_->address} = 1 for $packet->additional;

    while (my ($k, $v) = each %authority) {
        foreach my $addr (keys %$v) {
            next if $chain->{$addr};
            $chain->{$addr} = 1;
            return $self->parent->dns->query_explicit($name, $class, $type, $addr);
        }
    }

    foreach my $rr (grep {$_->type eq 'NS'} $packet->authority) {
        my @addrs = $self->parent->dns->find_addresses($rr->nsdname, 'IN');
        foreach my $addr (@addrs) {
            next if $authority{$rr->nsdname}{$addr}; # We already tried this
            next if $chain->{$addr};                 # Really, we tried this already!
            $chain->{$addr} = 1;
            return $self->parent->dns->query_explicit($name, $class, $type, $addr);
        }
    }

    return;
}

1;

__END__


=head1 NAME

DNSCheck::Test::Delegation - Test zone delegation

=head1 DESCRIPTION

Test zone delegation. The following tests are made:

=over 4

=item *
All nameservers at parent must exist at child.

=item *
Nameservers at child may exist at parent.

=item *
# REQUIRE: at least two (2) NS records at parent [IIS.KVSE.001.01/r1]

=item *
# REQUIRE: check for inconsistent glue

=back

=head1 METHODS

=over

=item ->test($zonename, $historyarrayref)

Run the default set of delegation tests on the given domain with the specified
history.

=item ->ns_parent_child_matching($zonename)

Only run the tests checking if the parent and child nameserver information
matches. Returns a two-element list, with the first element being the number
of problems at levels ERROR and CRITICAL, and the second element being a
boolean flag indicating if the zone is at all testable. If that flag is false,
there is not point in running any further tests, since they will almst
invariably fail.

=item ->consistent_glue($zonename)

Check that the glue records for the zone make sense.

=item ->enough_nameservers($zonename)

Check that there are a sufficient number of nameservers for the given zone.

=item ->check_history($zonename, $historyarrayref)

Go through the nameservers that used to be authoritative for this zone and
check that they no longer answer authoritatively for it.

=item ->cname_as_ns($zone)

Checks if any of the nameserver names for the given zone return CNAME records 
to A or AAAA queries.

=item ->in_zone_ns_glue($zone)

Checks that all in-zone nameserver records come with glue.

=item referral_size($zone)

Fetches NS data from child servers, and verifies that a referral packet of at most 512 octets can be built from the returned information.

=item _max_length_name_for($name)

Internal utility function (not method) that takes a domain name and returns a made-up maximally long name with the given name as a suffix.

=item min_packet_length($zone, %nsdata)

Takes the name of a zone and data about its nameservers, and returns the size in octets of the smallest functional referral packet that can
be built from the data given a query for a maximally long name. The C<%nsdata> hash should have nameservers names as keys, and references to
lists of strings with IP addresses (v4 and v6) as values.

=item follow_referral()

Internal helper method.

=back

Where nothing else is said, all methods return the total number of errors
found at levels ERROR and CRITICAL.

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>

=cut
