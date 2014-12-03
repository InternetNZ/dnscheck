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

package DNSCheck::Lookup::DNS;

use strict;
use utf8;
use warnings;
require 5.010001;

use List::Util 'shuffle';
use Carp;

use Data::Dumper;
use Net::DNS 0.59;
use Net::IP 1.25;

use Crypt::OpenSSL::Random qw(random_bytes);
use Digest::SHA qw(sha1);
use Digest::BubbleBabble qw(bubblebabble);

# Unneccesary uses to placate Perl::Critic
use DNSCheck::Lookup::Resolver;
use Net::DNS::Resolver;

######################################################################

sub new {
    my $proto = shift;
    my $class = ref( $proto ) || $proto;
    my $self  = {};
    bless $self, $class;

    my $parent = shift;

    $self->{_parent} = $parent;
    my $config = $parent->config;

    $self->{debug} = $config->get( "debug" );

    if ( $self->{debug} && $self->{debug} >= 2 ) {
        $self->{debug_resolver} = 1;
    }
    else {
        $self->{debug_resolver} = 0;
    }

    # hash PACKET at resolver indexed by QNAME,QTYPE,QCLASS
    $self->{cache}{resolver} = ();

    # hash PACKET at parent indexed by QNAME,QTYPE,QCLASS
    $self->{cache}{parent} = ();

    # hash PACKET at child indexed by QNAME,QTYPE,QCLASS
    $self->{cache}{child} = ();

    # hash of NAMESERVERS index QNAME,QCLASS,PROTOCOL
    $self->{nameservers} = ();

    # hash of PARENT indexed by CHILD,QCLASS
    $self->{parent} = ();

    # hash of SOMETHING indexed by ADDRESSES
    $self->{blacklist} = ();

    $self->{default} = $parent->config->get( "dns" );

    # set up global resolver
    $self->{resolver} = $parent->resolver;

    return $self;
}

######################################################################

sub flush {
    my $self = shift;

    $self->{cache}{resolver} = ();
    $self->{cache}{parent}   = ();
    $self->{cache}{child}    = ();
    $self->{blacklist}       = ();

    return;
}

sub parent {
    my $self = shift;

    return $self->{_parent};
}

sub logger {
    my $self = shift;

    return $self->parent->logger;
}

sub resolver {
    my $self = shift;

    return $self->{resolver};
}

######################################################################

sub query_resolver {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;

    $self->logger->auto( "DNS:QUERY_RESOLVER", $qname, $qclass, $qtype );

    unless ( $self->{cache}{resolver}{$qname}{$qclass}{$qtype} ) {
        $self->{cache}{resolver}{$qname}{$qclass}{$qtype} =
          $self->{resolver}->recurse( $qname, $qtype, $qclass );

        if ( $self->check_timeout( $self->{resolver} ) ) {
            $self->logger->auto( "DNS:RESOLVER_QUERY_TIMEOUT", $qname, $qclass, $qtype );
            return;
        }
    }

    my $packet = $self->{cache}{resolver}{$qname}{$qclass}{$qtype};

    if ( $packet ) {
        $self->logger->auto( "DNS:RESOLVER_RESPONSE", sprintf( "%d answer(s)", scalar( $packet->answer ) ) );
    }

    return $packet;
}

######################################################################

sub query_parent {
    my $self   = shift;
    my $zone   = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;

    $self->logger->auto( "DNS:QUERY_PARENT", $zone, $qname, $qclass, $qtype );

    unless ( $self->{cache}{parent}{$zone}{$qname}{$qclass}{$qtype} ) {
        $self->{cache}{parent}{$zone}{$qname}{$qclass}{$qtype} =
          $self->query_parent_nocache( $zone, $qname, $qclass, $qtype );
    }

    my $packet = $self->{cache}{parent}{$zone}{$qname}{$qclass}{$qtype};

    if ( $packet ) {
        $self->logger->auto( "DNS:PARENT_RESPONSE", sprintf( "%d answer(s), %d authority", scalar( $packet->answer ), scalar( $packet->authority ) ) );
    }

    return $packet;
}

sub query_parent_nocache {
    my $self   = shift;
    my $zone   = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;
    my $flags  = shift;

    $self->logger->auto( "DNS:QUERY_PARENT_NOCACHE", $zone, $qname, $qclass, $qtype );

    if ( my @ns = $self->parent->resolver->faked_zone( $zone ) ) {
        if ( $qtype eq 'NS' ) {
            die "Looking for NS from parent for faked domain.\n";
        }
        elsif ( ( $qtype eq 'A' or $qtype eq 'AAAA' ) and ( grep { /\Q$qname\E/ } @ns ) ) {
            my $p = $self->parent->resolver->fake_packet( $zone, $qname, $qtype );
            return $p if defined( $p );
        }
        elsif ( $qtype eq 'DS' ) {
            return $self->parent->resolver->fake_ds_packet( $zone );
        }
    }

    # find parent
    $self->logger->auto( "DNS:FIND_PARENT", $zone, $qclass );
    my $parent = $self->find_parent( $zone, $qclass );
    unless ( $parent ) {
        $self->logger->auto( "DNS:NO_PARENT", $zone, $qclass );
        return;
    }
    else {
        $self->logger->auto( "DNS:PARENT_OF", $parent, $zone, $qclass );
    }

    # initialize parent nameservers
    $self->init_nameservers( $parent, $qclass );

    # find parent to query
    my $ipv4 = $self->get_nameservers_ipv4( $parent, $qclass );
    my $ipv6 = $self->get_nameservers_ipv6( $parent, $qclass );
    my @target = ();
    @target = ( @target, @{$ipv4} ) if ( $ipv4 );
    @target = ( @target, @{$ipv6} ) if ( $ipv6 );
    unless ( scalar @target ) {
        $self->logger->auto( "DNS:NO_PARENT_NS", $parent, $zone, $qclass );
        return;
    }

    # randomize name server addresses
    @target = shuffle( @target );

    return $self->_query_multiple( $qname, $qclass, $qtype, $flags, @target );
}

######################################################################

sub query_child {
    my $self   = shift;
    my $zone   = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;

    $self->logger->auto( "DNS:QUERY_CHILD", $zone, $qname, $qclass, $qtype );

    unless ( $self->{cache}{child}{$zone}{$qname}{$qclass}{$qtype} ) {
        $self->{cache}{child}{$zone}{$qname}{$qclass}{$qtype} =
          $self->query_child_nocache( $zone, $qname, $qclass, $qtype );
    }

    my $packet = $self->{cache}{child}{$zone}{$qname}{$qclass}{$qtype};

    if ( $packet ) {
        $self->logger->auto( "DNS:CHILD_RESPONSE", sprintf( "%d answer(s)", scalar( $packet->answer ) ) );
    }

    return $packet;
}

sub query_child_nocache {
    my $self   = shift;
    my $zone   = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;
    my $flags  = shift;
    my $parent = $self->parent;

    $self->logger->auto( "DNS:QUERY_CHILD_NOCACHE", $zone, $qname, $qclass, $qtype );

    # initialize child nameservers
    $self->init_nameservers( $zone, $qclass );

    # find child to query
    my @target = ();

    my $ipv4 = $self->get_nameservers_ipv4( $zone, $qclass );
    my $ipv6 = $self->get_nameservers_ipv6( $zone, $qclass );
    @target = ( @target, @{$ipv4} ) if ( $ipv4 );
    @target = ( @target, @{$ipv6} ) if ( $ipv6 );

    unless ( scalar @target ) {
        $self->logger->auto( "DNS:NO_CHILD_NS", $zone, $qclass );
        return;
    }

    $flags->{aaonly} = 1;

    return $self->_query_multiple( $qname, $qclass, $qtype, $flags, @target );
}

######################################################################

sub query_explicit {
    my $self    = shift;
    my $qname   = shift;
    my $qclass  = shift;
    my $qtype   = shift;
    my $address = shift;
    my $flags   = shift;

    $self->logger->auto( "DNS:QUERY_EXPLICIT", $address, $qname, $qclass, $qtype );

    unless ( $self->_querible( $address ) ) {
        return;
    }

    my $resolver = $self->_setup_resolver( $flags );

    # $resolver->nameserver($address);

    if ( $self->check_blacklist( $address, $qname, $qclass, $qtype ) ) {
        $self->logger->auto( "DNS:ADDRESS_BLACKLISTED", $address, $qname, $qclass, $qtype );
        return;
    }

    my $packet = $resolver->get( $qname, $qtype, $qclass, $address );

    if ( $self->check_timeout( $resolver ) ) {
        $self->logger->auto( "DNS:QUERY_TIMEOUT", $address, $qname, $qclass, $qtype );
        $self->add_blacklist( $address, $qname, $qclass, $qtype );
        $self->logger->auto( "DNS:ADDRESS_BLACKLIST_ADD", $address, $qname, $qclass, $qtype );
        return;
    }

    unless ( $packet ) {
        $self->logger->auto( "DNS:LOOKUP_ERROR", $resolver->errorstring );
        return;
    }

    # FIXME: improve; see RFC 2671 section 5.3
    # FIXME: Can FORMERR appear when called from Nameserver.pm?
    #        I.e. returning undef would generate NO_TCP/NO_UDP
    if ( $packet->header->rcode eq "FORMERR"
        && ( $flags->{bufsize} || $flags->{dnssec} ) )
    {
        $self->logger->auto( "DNS:NO_EDNS", $address );
        return;
    }

    # FIXME: improve; see RFC 2671 section 5.3
    if ( $packet->header->rcode eq "FORMERR" ) {
        $self->logger->auto( "DNS:LOOKUP_ERROR", $resolver->errorstring );
        return;
    }

    # FIXME: Returns $packet since we don't want NAMESERVER:NO_TCP/NO_UDP
    # ALMOST REMOVE: If we blacklist on SOA SERVFAIL, we get false negative for NOT_AUTH
    if ( $packet->header->rcode eq "SERVFAIL" && uc( $qtype ) eq "SOA" ) {
        unless ( defined( $flags ) && $flags->{noservfail} ) {
            $self->logger->auto( "DNS:SOA_SERVFAIL", $address );
        }
        return $packet;
    }

    # FIXME: notice, warning, error?
    if ( $packet->header->rcode ne "NOERROR" ) {
        $self->logger->auto( "DNS:NO_ANSWER", $address, $qname, $qclass, $qtype );
    }

    # ignore non-authoritative answers unless flag aaonly is unset
    unless ( $packet && $packet->header->aa ) {
        if ( $flags && $flags->{aaonly} ) {
            unless ( $flags->{aaonly} == 0 ) {
                $self->logger->auto( "DNS:NOT_AUTH", $address, $qname, $qclass, $qtype );
                return;
            }
        }
    }

    $self->logger->auto( "DNS:EXPLICIT_RESPONSE", sprintf( "%d answer(s)", scalar( $packet->answer ) ) );

    foreach my $rr ( $packet->answer ) {
        $self->logger->auto( "DNS:ANSWER_DUMP", _rr2string( $rr ) );
    }

    return $packet;
}

######################################################################

sub _query_multiple {
    my ( $self, $qname, $qclass, $qtype, $flags, @target ) = @_;

    # set up resolver
    my $resolver = $self->_setup_resolver( $flags );

    my $packet  = undef;
    my $timeout = 0;

    for my $address ( @target ) {
        unless ( $self->_querible( $address ) ) {
            next;
        }

        $packet = $resolver->get( $qname, $qtype, $qclass, $address );

        # ignore non-authoritative answers if flag aaonly is set
        unless ( $packet && $packet->header->aa ) {
            if ( $flags && $flags->{aaonly} ) {
                if ( $flags->{aaonly} == 1 ) {
                    $self->logger->auto( "DNS:NOT_AUTH", $address, $qname, $qclass, $qtype );
                    next;
                }
            }
        }

        last if ( $packet && $packet->header->rcode ne "SERVFAIL" );

        if ( $self->check_timeout( $resolver ) ) {
            $timeout++;
        }
    }

    unless ( $packet && $packet->header->rcode ne "SERVFAIL" ) {
        if ( $timeout ) {
            $self->logger->auto( "DNS:QUERY_TIMEOUT", join( ",", @target ), $qname, $qclass, $qtype );
        }
        else {
            $self->logger->auto( "DNS:LOOKUP_ERROR", $resolver->errorstring );
        }
    }

    return $packet;
}

######################################################################

sub _setup_resolver {
    my $self  = shift;
    my $flags = shift;

    $self->logger->auto( "DNS:SETUP_RESOLVER" );

    # set up resolver
    my $resolver = DNSCheck::Lookup::Resolver->new( $self->parent );

    $resolver->resolver->cdflag( 1 );
    $resolver->resolver->usevc( 0 );
    $resolver->resolver->defnames( 0 );

    if ( $flags ) {
        if ( $flags->{transport} ) {
            if ( $flags->{transport} eq "udp" ) {
                $resolver->resolver->usevc( 0 );
            }
            elsif ( $flags->{transport} eq "tcp" ) {
                $resolver->resolver->usevc( 1 );
            }
            else {
                die "unknown transport";
            }

            if ( $flags->{transport} eq "udp" && $flags->{bufsize} ) {
                $self->logger->auto( "DNS:SET_BUFSIZE", $flags->{bufsize} );
                $resolver->resolver->udppacketsize( $flags->{bufsize} );
            }
        }

        # if ($flags->{recurse}) {
        #    $resolver->recurse(1);
        # }

        if ( $flags->{dnssec} ) {
            $resolver->dnssec( 1 );
        }

        if ( $flags->{nsid} ) {
            $resolver->nsid( 1 );
        }
    }

    if ( $resolver->resolver->usevc ) {
        $self->logger->auto( "DNS:TRANSPORT_TCP" );
    }
    else {
        $self->logger->auto( "DNS:TRANSPORT_UDP" );
    }

    # if ($resolver->recurse) {
    #     $self->logger->auto("DNS:RECURSION_DESIRED");
    # } else {
    #     $self->logger->auto("DNS:RECURSION_DISABLED");
    # }

    # if ($resolver->resolver->dnssec) {
    #     $self->logger->auto("DNS:DNSSEC_DESIRED");
    # } else {
    #     $self->logger->auto("DNS:DNSSEC_DISABLED");
    # }

    return $resolver;
}

######################################################################

sub get_nameservers_ipv4 {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    $self->init_nameservers( $qname, $qclass );

    return $self->{nameservers}{$qname}{$qclass}{ipv4};
}

sub get_nameservers_ipv6 {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    $self->init_nameservers( $qname, $qclass );

    return $self->{nameservers}{$qname}{$qclass}{ipv6};
}

sub get_nameservers_at_parent {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    my @ns;
    my $ttl = -1;

    $self->logger->auto( "DNS:GET_NS_AT_PARENT", $qname, $qclass );

    if ( $self->parent->undelegated_test or $self->resolver->faked_zone( $qname ) ) {
        my @tmp = sort $self->resolver->faked_zone( $qname );
        return (\@tmp, $ttl);
    }

    my $packet = $self->query_parent( $qname, $qname, $qclass, "NS" );

    return ( [], $ttl ) unless ( $packet );

    if ( $packet->authority > 0 ) {
        foreach my $rr ( $packet->authority ) {
            if ( ( $rr->type eq "NS" ) && $rr->nsdname ) {
                push @ns, $rr->nsdname;
                $ttl = $rr->ttl;
            }
        }
    }
    else {
        foreach my $rr ( $packet->answer ) {
            if ( ( $rr->type eq "NS" ) && $rr->nsdname ) {
                push @ns, $rr->nsdname;
                $ttl = $rr->ttl;
            }
        }
    }

    my @tmp = sort( @ns );
    return ( \@tmp, $ttl );
}

sub get_nameservers_at_child {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    my @ns;
    my $ttl = -1;

    $self->logger->auto( "DNS:GET_NS_AT_CHILD", $qname, $qclass );

    my $packet = $self->query_child( $qname, $qname, $qclass, "NS" );

    return ( [], $ttl ) unless ( $packet );

    foreach my $rr ( $packet->answer ) {
        if ( ( $rr->type eq "NS" ) && $rr->nsdname ) {
            push @ns, $rr->nsdname;
            $ttl = $rr->ttl;
        }
    }

    my @tmp = sort( @ns );
    return ( \@tmp, $ttl );
}

######################################################################

sub init_nameservers {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    unless ( $self->{nameservers}{$qname}{$qclass}{ns} ) {
        $self->_init_nameservers_helper( $qname, $qclass );
    }

    return;
}

sub _init_nameservers_helper {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    my %nsv4;
    my %nsv6;

    $self->logger->auto( "DNS:INITIALIZING_NAMESERVERS", $qname, $qclass );

    $self->{nameservers}{$qname}{$qclass}{ns}   = ();
    $self->{nameservers}{$qname}{$qclass}{ipv4} = ();
    $self->{nameservers}{$qname}{$qclass}{ipv6} = ();

    # Lookup name servers
    my $ns = $self->query_resolver( $qname, $qclass, "NS" );

    # If we cannot find any nameservers, we're done
    goto DONE unless ( $ns );

    foreach my $rr ( $ns->answer ) {
        if ( ( $rr->type eq "NS" ) && $rr->nsdname ) {
            push @{ $self->{nameservers}{$qname}{$qclass}{ns} }, $rr->nsdname;
        }
    }

    goto DONE unless ( $self->{nameservers}{$qname}{$qclass}{ns} );

    foreach my $ns ( sort @{ $self->{nameservers}{$qname}{$qclass}{ns} } ) {

        # Lookup IPv4 addresses for name servers
        my $ipv4 = $self->query_resolver( $ns, $qclass, "A" );

        if ( defined( $ipv4 ) ) {
            foreach my $rr ( $ipv4->answer ) {
                if ( ( $rr->type eq "A" ) && $rr->address ) {
                    $nsv4{ $rr->address } = 1;
                    $self->logger->auto( "DNS:NAMESERVER_FOUND", $qname, $qclass, $rr->name, $rr->address );
                }
            }
        }

        # Lookup IPv6 addresses for name servers
        my $ipv6 = $self->query_resolver( $ns, $qclass, "AAAA" );

        if ( defined( $ipv6 ) ) {
            foreach my $rr ( $ipv6->answer ) {
                if ( ( $rr->type eq "AAAA" ) && $rr->address ) {
                    $nsv6{ $rr->address } = 1;
                    $self->logger->auto( "DNS:NAMESERVER_FOUND", $qname, $qclass, $rr->name, $rr->address );
                }
            }
        }
    }

  DONE:
    $self->{nameservers}{$qname}{$qclass}{ipv4} = [ keys %nsv4 ];
    $self->{nameservers}{$qname}{$qclass}{ipv6} = [ keys %nsv6 ]
      if ( keys %nsv6 ) > 0;
    return $self->logger->auto( "DNS:NAMESERVERS_INITIALIZED", $qname, $qclass );
}

######################################################################

sub find_parent {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    unless ( $self->{parent}{$qname}{$qclass} ) {
        $self->{parent}{$qname}{$qclass} =
          $self->_find_parent_helper( $qname, $qclass );
    }

    my $parent = $self->{parent}{$qname}{$qclass};

    return $parent;
}

sub _find_parent_helper {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    my $parent = undef;

    $self->logger->auto( "DNS:FIND_PARENT_BEGIN", $qname, $qclass );

    my ( $first, $second ) = $self->{resolver}->trace( $qname );
    if ( $first ) {
        if ( $first eq $qname or $first . '.' eq $qname ) {
            $parent = $second // '';
        }
        else {
            $parent = $first;
        }
    }

    if ( defined( $parent ) and $parent eq '' ) {
        $parent = '.';
    }

  DONE:
    if ( $parent ) {
        $self->logger->auto( "DNS:FIND_PARENT_RESULT", $parent, $qname, $qclass );
    }
    else {
        $self->logger->auto( "DNS:NXDOMAIN", $qname, $qclass );
    }

    return $parent;
}

######################################################################

sub find_mx {
    my $self   = shift;
    my $domain = shift;

    my $packet;
    my @dest = ();

    $self->logger->auto( "DNS:FIND_MX_BEGIN", $domain );

    $packet = $self->query_resolver( $domain, "IN", 'MX' );
    if ( $packet && scalar( $packet->answer ) > 0 ) {
        foreach my $rr ( $packet->answer ) {
            if ( ( $rr->type eq "MX" ) && $rr->exchange ) {
                push @dest, [ $rr->preference, $rr->exchange ];
            }
        }
        @dest = map { $_->[1] } sort { $a->[0] <=> $b->[0] } @dest;
        goto DONE if ( scalar @dest );
    }

    $packet = $self->query_resolver( $domain, "IN", 'A' );
    if ( $packet && scalar( $packet->answer ) > 0 ) {
        foreach my $rr ( $packet->answer ) {
            if ( $rr->type eq "A" ) {
                push @dest, $domain;
                goto DONE;
            }
        }
    }

    $packet = $self->query_resolver( $domain, "IN", 'AAAA' );
    if ( $packet && scalar( $packet->answer ) > 0 ) {
        foreach my $rr ( $packet->answer ) {
            if ( $rr->type eq "AAAA" ) {
                push @dest, $domain;
                goto DONE;
            }
        }
    }

  DONE:
    $self->logger->auto( "DNS:FIND_MX_RESULT", $domain, join( ",", @dest) );

    return @dest;
}

sub find_mx_with_ttl {
    my $self   = shift;
    my $domain = shift;

    my $packet;
    my @dest = ();
    my %ttl;

    $self->logger->auto( "DNS:FIND_MX_BEGIN", $domain );

    $packet = $self->query_resolver( $domain, "IN", 'MX' );
    if ( $packet && scalar( $packet->answer ) > 0 ) {
        foreach my $rr ( $packet->answer ) {
            if ( ( $rr->type eq "MX" ) && $rr->exchange ) {
                push @dest, [ $rr->preference, $rr->exchange ];
                $ttl{$rr->type} = $rr->ttl;
            }
        }
        @dest = map { $_->[1] } sort { $a->[0] <=> $b->[0] } @dest;
        goto DONE if ( scalar @dest );
    }

    $packet = $self->query_resolver( $domain, "IN", 'A' );
    if ( $packet && scalar( $packet->answer ) > 0 ) {
        foreach my $rr ( $packet->answer ) {
            if ( $rr->type eq "A" ) {
                push @dest, $domain;
                $ttl{$rr->type} = $rr->ttl;
                goto DONE;
            }
        }
    }

    $packet = $self->query_resolver( $domain, "IN", 'AAAA' );
    if ( $packet && scalar( $packet->answer ) > 0 ) {
        foreach my $rr ( $packet->answer ) {
            if ( $rr->type eq "AAAA" ) {
                push @dest, $domain;
                $ttl{$rr->type} = $rr->ttl;
                goto DONE;
            }
        }
    }

  DONE:
    my $ttl_str = join(' ', map { "$_:$ttl{$_}" } keys %ttl);
    $self->logger->auto( "DNS:FIND_MX_RESULT", $domain, join( ",", @dest), $ttl_str );

    return ( \@dest, $ttl_str );
}

sub find_addresses {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    my @addresses = ();

    $self->logger->auto( "DNS:FIND_ADDRESSES", $qname, $qclass );

    my $ipv4 = $self->query_resolver( $qname, $qclass, "A" );
    my $ipv6 = $self->query_resolver( $qname, $qclass, "AAAA" );

    unless ( ( $ipv4 && scalar( $ipv4->answer ) )
        || ( $ipv6 && scalar( $ipv6->answer ) ) )
    {
        ## FIXME: error
        goto DONE;
    }

    my @answers = ();
    push @answers, $ipv4->answer if ( defined( $ipv4 ) && scalar( $ipv4->answer ) );
    push @answers, $ipv6->answer if ( defined( $ipv6 ) && scalar( $ipv6->answer ) );

    foreach my $rr ( @answers ) {
        if ( ( $rr->type eq "A" or $rr->type eq "AAAA" ) && $rr->address ) {
            push @addresses, $rr->address;
        }
    }

  DONE:
    $self->logger->auto( "DNS:FIND_ADDRESSES_RESULT", $qname, $qclass, join( ",", @addresses ) );

    return @addresses;
}

sub find_addresses_with_ttl {
    my $self   = shift;
    my $qname  = shift;
    my $qclass = shift;

    my @addresses = ();
    my %addr_set;

    $self->logger->auto( "DNS:FIND_ADDRESSES", $qname, $qclass );

    my $ipv4 = $self->query_resolver( $qname, $qclass, "A" );
    my $ipv6 = $self->query_resolver( $qname, $qclass, "AAAA" );

    unless ( ( $ipv4 && scalar( $ipv4->answer ) )
        || ( $ipv6 && scalar( $ipv6->answer ) ) )
    {
        ## FIXME: error
        goto DONE;
    }

    my @answers = ();
    push @answers, $ipv4->answer if ( defined( $ipv4 ) && scalar( $ipv4->answer ) );
    push @answers, $ipv6->answer if ( defined( $ipv6 ) && scalar( $ipv6->answer ) );

    foreach my $rr ( @answers ) {
        if ( ( $rr->type eq 'A' || $rr->type eq 'AAAA' ) && $rr->address ) {
            push @addresses, $rr->address;
            my $family = ( $rr->type eq 'A' ? 4 : 6 );
            $addr_set{$family}{'ttl'} = $rr->ttl;
            push(@{$addr_set{$family}{'addr'}}, $rr->address);
        }
    }

  DONE:
    $self->logger->auto( "DNS:FIND_ADDRESSES_RESULT", $qname, $qclass, join( ",", @addresses ) );

    return \%addr_set;
}

######################################################################

sub address_is_authoritative {
    my $self    = shift;
    my $address = shift;
    my $qname   = shift;
    my $qclass  = shift;

    my $logger = $self->logger;
    my $errors = 0;

    my $packet = $self->query_explicit( $qname, $qclass, "SOA", $address, { transport => "udp", aaonly => 0 } );

    goto DONE unless ( $packet );

    # This means that REFUSED or SERVFAIL with the authoritative flag set will
    # register as the server being authoritative for the domain in question.
    if ( $packet->header->aa != 1 ) {
        $errors += 1;
        $self->logger->auto( "NAMESERVER:NOT_AUTH_UDP", $address );
    }
    else {
        $self->logger->auto( "NAMESERVER:AUTH_UDP", $address );
    }

  DONE:
    return $errors;
}

sub address_is_authoritative_tcp {
    my $self    = shift;
    my $address = shift;
    my $qname   = shift;
    my $qclass  = shift;

    my $logger = $self->logger;
    my $errors = 0;

    my $packet = $self->query_explicit( $qname, $qclass, "SOA", $address, { transport => "tcp", aaonly => 0 } );

    goto DONE unless ( $packet );

    # See above
    if ( $packet->header->aa != 1 ) {
        $errors += 1;
        $self->logger->auto( "NAMESERVER:NOT_AUTH_TCP", $address );
    }
    else {
        $self->logger->auto( "NAMESERVER:AUTH_TCP", $address );
    }

  DONE:
    return $errors;
}

sub address_is_recursive {
    my $self    = shift;
    my $address = shift;
    my $qclass  = shift;

    my $logger = $self->logger;
    my $errors = 0;

    # no blacklisting here, since some nameservers ignore recursive queries

    unless ( $self->_querible( $address ) ) {
        goto DONE;
    }

    my $resolver = DNSCheck::Lookup::Resolver->new( $self->parent );
    $resolver->recursion( 1 );
    $resolver->cdflag( 1 );

    # create nonexisting domain name
    my $nxdomain    = "nxdomain.example.com";
    my @tmp         = split( /-/, bubblebabble( Digest => sha1( random_bytes( 64 ) ) ) );
    my $nonexisting = sprintf( "%s.%s", join( "", @tmp[ 1 .. 6 ] ), $nxdomain );

    my $qtype = "SOA";
    my $packet = $resolver->get( $nonexisting, $qtype, $qclass, $address );
    if ( $self->check_timeout( $resolver ) ) {
        $self->logger->auto( "DNS:QUERY_TIMEOUT", $address, $nonexisting, $qclass, $qtype );
        goto DONE;
    }

    goto DONE unless $packet;

    ## recursion available zero is ok
    goto DONE if ( $packet->header->ra == 0 );

    ## refused and servfail is ok
    goto DONE if ( $packet->header->rcode eq "REFUSED" );
    goto DONE if ( $packet->header->rcode eq "SERVFAIL" );

    ## referral is ok
    goto DONE
      if (  $packet->header->rcode eq "NOERROR"
        and scalar( $packet->answer ) == 0
        and scalar( $packet->authority ) > 0 );

    $errors++;

  DONE:
    return $errors;
}

######################################################################

sub check_axfr {
    my $self    = shift;
    my $address = shift;
    my $qname   = shift;
    my $qclass  = shift;
    my $timeout;

    eval { $timeout = $self->parent->config->get( 'dns' )->{tcp_timeout} };
    $timeout //= 60;

    unless ( $self->_querible( $address ) ) {
        return 0;
    }

    # set up resolver
    my $resolver = Net::DNS::Resolver->new;
    $resolver->debug( $self->{debug_resolver} );
    $resolver->recurse( 0 );
    $resolver->dnssec( 0 );
    $resolver->usevc( 0 );
    $resolver->defnames( 0 );
    $resolver->tcp_timeout( $timeout );

    $resolver->nameservers( $address );
    $resolver->axfr_start( $qname, $qclass );

    if ( $resolver->axfr_next ) {
        return 1;
    }

    return 0;
}

######################################################################

sub query_nsid {
    my $self    = shift;
    my $address = shift;
    my $qname   = shift;
    my $qclass  = shift;
    my $qtype   = shift;


    unless ($self->_querible($address)) {
        return;
    }

    my $response = $self->query_explicit( $qname, $qclass, $qtype, $address, { nsid => 1 });

    # Query failed
    return [] unless ($response);

    # Response is empty
    return [] if ($response->header->ancount == 0);

    # No additional record came with the response
    return [] if (!$response->additional);

    #--------------
    # NSID data is binary and contains:
    # first two octets represent the option (3),
    # two octets representing the length of the ID
    # the rest is the ID
    my ($opt_id, $nsid_len, $nsid_str) = unpack("nna*", $response->pop('additional')->rdata);

    return [] if ($opt_id eq "");

    my ($hex_nsid, $print_nsid) = ('') x 2;
    # If the rdata makes sense
    if ($opt_id == 3 && $nsid_len > 0) {
        $hex_nsid = join("", map { sprintf "%02x", $_ }
                        unpack("C*", $nsid_str));
        # Remove all non-printable characters
        $print_nsid = $nsid_str =~ tr/[\0-\x08\x0B\x0C\x0E-\x1F\x7F]/ /r;
    }

    return [$hex_nsid, $print_nsid];
}


######################################################################

sub _rr2string {    # Why do this instead of using the native ->string method?
    my $rr = shift;
    my $rdatastr;

    if ( $rr->type eq "SOA" ) {
        $rdatastr = sprintf( "%s %s %d %d %d %d %d", $rr->mname, $rr->rname, $rr->serial, $rr->refresh, $rr->retry, $rr->expire, $rr->minimum );
    }
    elsif ( $rr->type eq "DS" ) {
        $rdatastr = sprintf( "%d %d %d %s", $rr->keytag, $rr->algorithm, $rr->digtype, $rr->digest );
    }
    elsif ( $rr->type eq "RRSIG" ) {
        $rdatastr = sprintf( "%s %d %d %d %s %s %d %s %s", $rr->typecovered, $rr->algorithm, $rr->labels, $rr->orgttl, $rr->sigexpiration, $rr->siginception, $rr->keytag, $rr->signame, "..." );
    }
    elsif ( $rr->type eq "DNSKEY" ) {
        $rdatastr = sprintf( "%d %d %d %s", $rr->flags, $rr->protocol, $rr->algorithm, "..." );
    }
    else {
        $rdatastr = $rr->rdatastr;
    }

    return sprintf( "%s %d %s %s %s", $rr->name, $rr->ttl, $rr->class, $rr->type, $rdatastr );
}

sub _querible {
    my $self    = shift;
    my $address = shift;
    my $conf    = $self->parent->config->get( "net" );

    my $ip = Net::IP->new( $address );

    if (   ( $ip->version == 4 and not $conf->{ipv4} )
        or ( $ip->version == 6 and not $conf->{ipv6} ) )
    {
        return 0;
    }
    else {
        return 1;
    }
}

######################################################################

sub clear_blacklist {
    my $self = shift;

    $self->{blacklist} = ();

    return;
}

sub add_blacklist {
    my $self   = shift;
    my $qaddr  = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;

    $self->{blacklist}{$qaddr}{$qname}{$qclass}{$qtype} = 1;

    return;
}

sub check_blacklist {
    my $self   = shift;
    my $qaddr  = shift;
    my $qname  = shift;
    my $qclass = shift;
    my $qtype  = shift;

    return 1 if ( $self->{blacklist}{$qaddr}{$qname}{$qclass}{$qtype} );
    return 0;
}

sub check_timeout {
    my $self = shift;
    my $res  = shift;

    return 1 if ( $res->errorstring eq "query timed out" );
    return 0;
}

######################################################################

sub preflight_check {
    my $self     = shift;
    my $resolver = $self->{resolver};
    my $name     = shift;

    my $packet = $resolver->recurse( $name, 'NS' );

    # Can we find an NS record?
    if ( defined( $packet )
        and grep { $_->type eq 'NS' or $_->type eq 'CNAME' } $packet->answer )
    {

        # Yup, return true
        return 1;
    }
    elsif ( !defined( $packet ) ) {

        # Transmission error or something similar, fail on the safe side.
        return 1;
    }

    $packet = $resolver->recurse( $name, 'SOA' );
    if ( defined( $packet )
        and grep { $_->type eq 'SOA' or $_->type eq 'CNAME' } $packet->answer )
    {
        return 1;
    }
    elsif ( !defined( $packet ) ) {
        return 1;
    }

    # Was it SERVFAIL? If it was, return true.
    if ( $resolver->errorstring eq 'SERVFAIL' ) {
        return 1;
    }

    # No NS, no SOA, no successful return
    return;
}

1;

__END__


=head1 NAME

DNSCheck::Lookup::DNS - DNS Lookup

=head1 DESCRIPTION

Helper functions for looking up information in the DNS (Domain Name System).

=head1 METHODS

=over

=item new($parent);

Create a new lookup object. Not recommended to use, create a L<DNSCheck>
object and call the L<DNSCheck::dns> method instead.

=item flush();

Empty the cache and clear the blacklist.

=item my $packet = $dns->query_resolver(I<qname>, I<qclass>, I<qtype>);

Send a query to the default resolver(s). This will be a L<DNSCheck::Lookup::Resolver> object.

=item my $packet = $dns->query_parent(I<zone>, I<qname>, I<qclass>, I<qtype>);

=item my $packet = $dns->query_child(I<zone>, I<qname>, I<qclass>, I<qtype>);

=item my $packet = $dns->query_explicit(I<qname>, I<qclass>, I<qtype>, I<address>, I<flags>);

=item my $addrs = $dns->get_nameservers_ipv4(I<qname>, I<qclass>);

=item my $addrs = $dns->get_nameservers_ipv6(I<qname>, I<qclass>);

=item my ( $ns, $ttl ) = $dns->get_nameservers_at_parent(I<qname>, I<qclass>);

=item my ( $ns, $ttl ) = $dns->get_nameservers_at_child(I<qname>, I<qclass>);

=item $dns->init_nameservers(I<qname>, I<qclass>);

=item my $parent = $dns->find_parent(I<qname>, I<qclass>);

=item my @mx = $dns->find_mail_destination(I<domain>);

=item my @addresses = $dns->find_addresses(I<qname>, I<qclass>);

=item my $bool = $dns->address_is_authoritative(I<address>, I<qname>, I<qtype>);

=item my $bool = $dns->address_is_recursive(I<address>, I<qclass>);

=item my $bool = $dns->check_axfr(I<address>, I<qname>, I<qclass>);

=item my ($hex_id, $print_id) = $dns->query_nsid(I<address>, I<qname>, I<qclass>, I<qtype>);

Queries an specific address for <qname, qclass, qtype> setting the NSID
(RFC 5001) option. If the response contains NSID info, it will return
the hex representation of the string, and a printable version.

=item ->add_blacklist($addr,$name,$class,$type)

Add the given quadruple to the internal blacklist.

=item ->check_blacklist($addr,$name,$class,$type)

Return a true value if the given quadruple is in the internal blacklist.

=item ->clear_blacklist()

Clear the internal blacklist.

=item ->check_timeout()

Check if the current error in the underlying resolver object is a timeout.

=item ->find_mx($zone)

Return the hostname(s) and ttl to which mail to the given zone name should be directed.

=item ->logger()

Return a reference to the current logger object.

=item ->parent()

Return a reference to the current parent object.

=item ->preflight_check($name)

Do a quick and dirty guess about if the given name is a zone or not.

=item ->query_child_nocache()

The same as L<query_child()>, but bypasses the internal cache.

=item ->query_parent_nocache()

The same as L<query_parent()>, but bypasses the internal cache.

=item ->resolver()

Returns a reference to the underlying L<DNSCheck::Lookup::Resolver> object.

=back

=head1 EXAMPLES

    use DNSCheck::Logger;
    use DNSCheck::Lookup::DNS;

    my $logger = new DNSCheck::Logger;
    my $dns    = new DNSCheck::Lookup::DNS($logger);

    my $parent = $dns->query_parent("nic.se", "ns.nic.se", "IN", "A");

    $logger->dump();

=head1 SEE ALSO

L<DNSCheck::Logger>, L<DNSCheck::Lookup::DNS>

=cut
