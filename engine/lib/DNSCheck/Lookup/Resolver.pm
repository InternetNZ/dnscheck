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

package DNSCheck::Lookup::Resolver;

require 5.010001;
use warnings;
use strict;
use utf8;

use YAML;
use Net::IP;
use Time::HiRes qw[gettimeofday tv_interval];
use Carp;
use Net::DNS::Resolver;
use Net::DNS::Packet;
use Net::DNS::RR;
use List::Util 'shuffle';

our %times;

# In order to be able to know for sure where certain information comes from,
# and/or modify parts of resolver chains, we need to do our own recursive
# lookups rather than rely on an external caching recursive resolver. This
# module is supposed to do recursive lookups. It seems to work, but was
# written by someone who is not a DNS expert, so comments on the module logic
# is very welcome.
sub new {
    my $class  = shift;
    my $parent = shift;
    my $self   = {};

    bless $self, $class;

    $self->{parent} = $parent;

    my $config = $self->config->get( "dns" );
    $self->{debug} = $parent->config->get( "debug" );
    $self->{debug} = $ENV{DNSCHECK_DEBUG} if $ENV{DNSCHECK_DEBUG};
    $self->{debug} -= 1 if $self->{debug};

    $self->{cache}   = $parent->config->get( 'root_zone_data' );
    $self->{current} = '';

    $self->{resolver} = Net::DNS::Resolver->new(

        # RFC3330 reserved address. As close to guaranteed *not* to have a nameserver
        # on it as we're likely to get (the module does not accept an empty list).
        nameservers => ['192.0.2.1'],
    );
    $self->{resolver}->persistent_tcp( 0 );
    $self->{resolver}->cdflag( 1 );
    $self->{resolver}->recurse( 0 );
    $self->{resolver}->dnssec( 0 );
    $self->{resolver}->debug( 1 ) if ( $self->{debug} and $self->{debug} > 1 );
    $self->{resolver}->udp_timeout( $config->{udp_timeout} );
    $self->{resolver}->tcp_timeout( $config->{tcp_timeout} );
    $self->{resolver}->retry( $config->{retry} );
    $self->{resolver}->retrans( $config->{retrans} );

    return $self;
}

# Standard utility methods
## no critic (Subroutines::RequireArgUnpacking)
sub resolver {
    return $_[0]->{resolver};
}

sub parent {
    return $_[0]->{parent};
}

sub cache {
    return $_[0]->{cache};
}

sub config {
    return $_[0]->parent->config;
}

sub logger {
    return $_[0]->parent->logger;
}

# Timing information

## no critic (Subroutines::ProhibitBuiltinHomonyms)
sub times {
    return \%times;
}

# Interface methods to underlying Net::DNS::Resolver object

sub errorstring {
    my $self = shift;

    return $self->resolver->errorstring( @_ );
}

sub dnssec {
    my $self = shift;

    return $self->resolver->dnssec( @_ );
}

sub recursion {
    my $self = shift;

    return $self->resolver->recurse( @_ );
}

sub cdflag {
    my $self = shift;

    return $self->resolver->cdflag( @_ );
}

sub nsid {
    my $self = shift;

    if (@_) {
        $self->{optrr} = new Net::DNS::RR (
            type => 'OPT',
            name => '',
            optioncode => 3, # NSID == 3
        );
    }
    else {
        return (defined $self->{optrr});
    }
}

# Methods to support undelegated testing

sub add_fake_glue {
    my $self   = shift;
    my $zone   = shift;
    my $nsname = shift;
    my $nsip   = shift;

    return unless Net::IP->new( $nsip );

    $nsname = $self->canonicalize_name( $nsname );
    $zone   = $self->canonicalize_name( $zone );

    $self->cache->{ns}{$zone}{$nsname}  = 1;
    $self->cache->{ips}{$nsname}{$nsip} = 1;
    $self->{fake}{ns}{$zone}            = 1;
    $self->{fake}{ips}{$nsname}         = 1;

    return $self;
}

sub add_fake_ds {
    my $self = shift;
    my $ds   = shift;

    push @{ $self->{fake}{ds}{ $ds->name } }, $ds;

    return $self;
}

# Return a list of zones with fake glue
sub faked_zones {
    my $self = shift;

    return map { my $tmp = $_; $tmp =~ s/\.$//; $tmp } keys %{ $self->{fake}{ns} };
}

# Return a list of NS names for a zone with fake glue
sub faked_zone {
    my $self = shift;
    my $name = shift;

    return unless $name;    # An empty name isn't a faked zone.

    $name = $self->canonicalize_name( $name );

    if ( $self->{fake}{ns}{$name} ) {
        return map { my $tmp = $_; $tmp =~ s/\.$//; $tmp }
          keys %{ $self->cache->{ns}{$name} };
    }
    else {
        return;
    }
}

# Return a made-up packet with information for a name
sub fake_packet {
    my $self = shift;
    my $zone = shift;
    my $name = shift;
    my $type = shift;

    $name = $self->canonicalize_name( $name );

    my @ns  = $self->faked_zone( $zone );
    my @ips = keys %{ $self->cache->{ips}{$name} };
    my $version;

    if ( $type eq 'A' ) {
        $version = 4;
    }
    elsif ( $type eq 'AAAA' ) {
        $version = 6;
    }
    elsif ( $type eq 'NS' ) {
        return $self->fake_ns_packet( $name );
    }
    else {
        return;    # Can't or won't fake that
    }

    @ips =
      map { $_->ip }
      grep { defined( $_ ) and $_->version == $version }
      map { Net::IP->new( $_ ) } @ips;

    my $p = Net::DNS::Packet->new;

    $p->unique_push( 'answer', Net::DNS::RR->new( "$name 4711 IN $type $_" ) ) for @ips;

    for my $ns ( @ns ) {
        $p->unique_push( 'authority', Net::DNS::RR->new( "$zone 4711 IN NS $ns" ) );
        for my $ip ( keys %{ $self->cache->{ips}{ $self->canonicalize_name( $ns ) } } ) {
            my $t = ( Net::IP->new( $ip )->version == 4 ) ? 'A' : 'AAAA';
            $p->unique_push( 'additional', Net::DNS::RR->new( "$ns 4711 IN $t $ip" ) );
        }
    }

    $p->header->aa( 1 );

    return $p;
}

sub fake_ns_packet {
    my $self = shift;
    my $zone = shift;
    my @ns   = keys %{ $self->{cache}{ns}{$zone} };

    my $p = Net::DNS::Packet->new;
    foreach my $n ( @ns ) {
        $p->unique_push( 'answer', Net::DNS::RR->new( "$zone 4711 IN NS $n" ) );
        foreach my $ip ( keys %{ $self->{cache}{ips}{$n} } ) {
            my $t = ( Net::IP->new( $ip )->version == 4 ) ? 'A' : 'AAAA';
            $p->unique_push( 'additional', Net::DNS::RR->new( "$n 4711 IN $t $ip" ) );
        }
    }

    return $p;
}

sub fake_ds_packet {
    my $self = shift;
    my $zone = shift;

    my $p = Net::DNS::Packet->new;
    foreach my $rr ( @{ $self->{fake}{ds}{$zone} } ) {
        $p->unique_push( 'answer', $rr );
    }

    return $p;
}

# Add stuff to our cache.
#
# We cache known nameserver lists for names, and IP addresses for names.
sub remember {
    my ( $self, $p ) = @_;

    return unless defined( $p );

    foreach my $rr ( $p->answer, $p->additional, $p->authority ) {
        my $n = $self->canonicalize_name( $rr->name );
        if ( $rr->type eq 'A' or $rr->type eq 'AAAA' ) {
            $self->{cache}{ips}{$n}{ Net::IP->new( $rr->address )->ip } = 1
              unless $self->{fake}{ips}{$n};
        }
        if ( $rr->type eq 'NS' ) {
            print STDERR "remember: NS $n (" . $rr->name . ") " . $rr->nsdname . ".\n"
              if ( $self->{debug} and $self->{debug} > 1 );
            $self->{cache}{ns}{$n}{ $self->canonicalize_name( $rr->nsdname ) } = 1
              unless $self->{fake}{ns}{$n};
        }
    }

    return $self;
}

# Class method to generate data with which to preload the cache.
sub get_preload_data {
    my $self   = shift;
    my $source = shift;
    my %cache;

    my $res = Net::DNS::Resolver->new;
    $res->nameservers( $source ) if defined( $source );
    my $z = eval { $res->send( '.', 'IN', 'NS' ) };

    if ( not defined( $z ) or scalar( $z->answer ) == 0 ) {
        croak "Failed to get root zone data";
    }

    foreach my $rr ( $z->answer ) {
        next unless $rr->type eq 'NS';

        $cache{ns}{'.'}{ $self->canonicalize_name( $rr->nsdname ) } = 1;
    }

    foreach my $nsname ( keys %{ $cache{ns}{'.'} } ) {
        $nsname = $self->canonicalize_name( $nsname );

        my $a = eval { $res->send( $nsname, 'IN', 'A' ) };
        next if ( not defined( $a ) or scalar( $a->answer ) == 0 );
        foreach my $rr ( $a->answer ) {
            next unless $rr->type eq 'A';

            $cache{ips}{$nsname}{ $rr->address } = 1;
        }

        my $aaaa = eval { $res->send( $nsname, 'IN', 'AAAA' ) };
        next if ( not defined( $aaaa ) or scalar( $aaaa->answer ) == 0 );
        foreach my $rr ( $aaaa->answer ) {
            next unless $rr->type eq 'AAAA';

            $cache{ips}{$nsname}{ $rr->address } = 1;
        }
    }

    return \%cache;
}

# Reformat a name into a standardized form, for ease of comparison
sub canonicalize_name {
    my $self = shift;
    my $name = shift;

    my $i = Net::IP->new( $name );
    if ( $name and $name =~ m|^[0-9.:]+$| and defined( $i ) ) {
        $name = $i->reverse_ip;
    }

    $name = lc( $name );

    $name .= '.' unless substr( $name, -1 ) eq '.';

    return $name;
}

# Strip the leftmost label off a DNS name. If there are no labels left after
# removing one, returns a single period for the root level.
sub strip_label {
    my $self = shift;
    my $name = shift;

    my @labels = split /\./, $name;
    shift @labels;

    if ( @labels ) {
        return $self->canonicalize_name( join '.', @labels );
    }
    else {
        return '.';
    }
}

# Take a name, and return the nameserver names for the highest parent level we
# have in cache. Which, at worst, will be the root zone, the data for which we
# initialize on object creation.
sub highest_known_ns {
    my $self = shift;
    my $name = shift;

    $name = $self->canonicalize_name( $name );

    # If there are more than one zone with fake glue, and one is a parent of
    # another, choose the one with the most labels in it.
    my $faked = (
        sort { $b =~ y/././ <=> $a =~ y/././ }
        grep { $name =~ /\Q$_\E$/ } $self->faked_zones
    )[0];

    if ( $faked ) {
        return keys %{ $self->cache->{ns}{$faked} };
    }

    my @candidates;
    while ( 1 ) {
        my @tmp;
        @tmp = $self->simple_names_to_ips( keys %{ $self->{cache}{ns}{$name} } )
          if $self->{cache}{ns}{$name};
        push @candidates, @tmp if @tmp;

        if ( $name eq '.' ) {
            last;
        }

        $name = $self->strip_label( $name );
    }

    if ( !@candidates ) {
        die "Root zone cache missing.";
    }
    else {
        return @candidates;
    }
}

sub simple_names_to_ips {
    my $self = shift;
    my @names = map { $self->canonicalize_name( $_ ) } @_;
    my @ips;

    foreach my $n ( @names ) {
        if ( $self->cache->{ips}{$n} ) {
            push @ips, keys %{ $self->cache->{ips}{$n} };
        }
    }

    return shuffle(@ips);
}

sub names_to_ips {
    my $self = shift;
    my @names = map { $self->canonicalize_name( $_ ) } @_;
    my @ips;

    foreach my $n ( @names ) {
        if ( $self->cache->{ips}{$n} ) {
            push @ips, keys %{ $self->cache->{ips}{$n} };
        }
        else {
            next if $self->{poison}{$n};
            $self->{poison}{$n} = 1;    # Block lookups of this name

            my $p = $self->recurse( $n, 'A' );
            $self->remember( $p );

            $p = $self->recurse( $n, 'AAAA' );
            $self->remember( $p );

            if ( $self->cache->{ips}{$n} ) {
                push @ips, keys %{ $self->cache->{ips}{$n} };
                $self->{poison}{$n} = 0;    # Allow lookups of name
            }
        }
    }

    return @ips;
}

# Send a query to a specified set of nameservers and return the result.
sub get {
    my $self  = shift;
    my $name  = shift;
    my $type  = shift // 'NS';
    my $class = shift // 'IN';
    my @ns    = @_;

    print STDERR "get: $name $type $class @ns " . ( caller( 1 ) )[3] . "\n"
      if $self->{debug};

    @ns =
      map { $_->ip }
      grep { ( $_->version == 4 and $self->config->get( 'net' )->{ipv4} ) or ( $_->version == 6 and $self->config->get( 'net' )->{ipv6} ) }
      map { Net::IP->new( $_ ) } @ns;

    return unless @ns;

    my @ns_old = $self->{resolver}->nameservers;
    $self->{resolver}->nameservers( @ns ) if @ns;

    # If the NSID flag is set, we need to prepare a packet in advance
    my $qry_pkt = new Net::DNS::Packet( $name, $class, $type );
    if ($self->nsid) {
        # Add the OPT RR to the packet
        $qry_pkt->unique_push(additional => $self->{optrr});
    }

    my $before   = [ gettimeofday() ];
    my $p        = eval { $self->{resolver}->send( $qry_pkt ) };
    my $duration = tv_interval( $before );

    if ( $p and $p->answerfrom ) {
        push @{ $self->times->{ $p->answerfrom } }, $duration;
    }

    print STDERR "get: " . $p->string . "\n"
      if ( defined( $p ) and $self->{debug} and $self->{debug} > 1 );
    $self->remember( $p ) if defined( $p );

    $self->{resolver}->nameservers( @ns_old );
    return $p;
}

sub trace {
    my ( $self, $domain ) = @_;

    $self->{trace}{$domain} = [];
    $self->recurse( $domain, 'ANY', 'ANY' );

    return reverse @{ $self->{trace}{$domain} };
}

# Recursively look up stuff.
#
# Resolution procedure of a name
# ==============================
#
# 1. Get ns names for the highest level we know of (root, probably).
#
# 2. Do name-to-ip for names. Discard names we can't translate.
#
# 3. Push IPs on stack of servers to ask, unless they've already been there.
#
# 4. Pop IP from stack. Send question to it. Remember we asked it.
#    If the stack is empty, return undef.
#
# 5. If we get a response, clear the stack.
#
# 6. If the reply is authoritative, return it.
#    If it is not, but contains records in Authority section, get names from
#    those records and go to 2, unless the records point to a name higher in
#    the chain, in which case we terminate and return undef.

sub recurse {
    my ( $self, $name, $type, $class, $cnames ) = @_;
    $type   //= 'NS';
    $class  //= 'IN';
    $cnames //= {};

    print STDERR "recurse: $name $type $class\n" if $self->{debug};

    # See if it should be faked
    if ( ( $type eq 'A' or $type eq 'AAAA' )
        and $self->{fake}{ips}{ $self->canonicalize_name( $name ) } )
    {
        return $self->fake_packet( undef, $name, $type );
    }
    elsif ( $type eq 'NS'
        and $self->{fake}{ns}{ $self->canonicalize_name( $name ) } )
    {
        return $self->fake_packet( undef, $name, $type );
    }

    my @stack = $self->highest_known_ns( $name );
    my %seen;
    my $candidate;

    my $level = -1;

    while ( @stack ) {
        my $ns = pop( @stack );
        print STDERR "recurse: Popped $ns (stack is " . scalar( @stack ) . " entries deep).\n"
          if $self->{debug};
        $seen{$ns} = 1;
        my $p = $self->get( $name, $type, $class, $ns );

        if ( !defined( $p ) ) {
            print STDERR "recurse: No response packet.\n" if $self->{debug};
            next;
        }
        elsif ( $p->header->rcode ne 'NOERROR' ) {
            print STDERR "recurse: Response code " . $p->header->rcode . "\n"
              if $self->{debug};
            $candidate = $p unless $candidate;
            next;
        }
        elsif ( scalar( $p->answer ) > 0 and grep { $_->type eq 'CNAME' } $p->answer ) {
            print STDERR "recurse: Resolving non-auth CNAME.\n"
              if $self->{debug};
            my $cnamerr = ( grep { $_->type eq 'CNAME' } $p->answer )[0];
            return $p if $cnames->{ $cnamerr->cname };    # Break loops
            $cnames->{ $cnamerr->cname } = 1;
            my $tmp = $self->recurse( $cnamerr->cname, $type, $class, $cnames );
            if ( $tmp ) {
                print STDERR "recurse: Adding CNAME to response packet.\n"
                  if $self->{debug};
                $tmp->unique_push( answer => $cnamerr )
                  unless ( keys %$cnames ) > 1;
                return $tmp;
            }
            else {
                return $p;
            }
        }
        elsif ( $self->matches( $p, $name, $type, $class ) ) {
            return $p;
        }
        elsif ( scalar( $p->authority ) > 0 ) {

            my $zname = ( $p->authority )[0]->name;
            my $m = $self->matching_labels( $name, $zname );

            if ( $m < $level ) {
                print STDERR "recurse: Bad referral. Skipping to next server.\n"
                  if $self->{debug};
                next;    # Resolving chain redirecting up
            }

            push @{ $self->{trace}{$name} }, $zname;    # Remember the path we took, so we can use it to find parent domains.
            $level = $m;

            print STDERR "recurse: Got " . scalar( $p->authority ) . " authority records. Reloading stack.\n"
              if $self->{debug};
            @stack = ();

            $self->remember( $p );
            if ( my @fns = $self->faked_zone( $zname ) ) {
                push @stack, grep { !$seen{$_} } $self->simple_names_to_ips( @fns );
            }
            else {
                push @stack,
                  grep { !$seen{$_} } $self->names_to_ips(
                    map  { $_->nsdname }
                    grep { $_->type eq 'NS' } $p->authority
                  );
            }
            next;
        }
        else {
            print STDERR "recurse: Fell through: " . $p->print
              if $self->{debug};
        }
    }

    print STDERR "recurse: Ran out of servers.\n" if $self->{debug};

    # Ran out of servers before we got a good reply, return what we've got
    if ( $candidate ) {
        return $candidate;
    }
    else {
        return;
    }
}

sub matches {
    my ( $self, $p, $name, $type, $class ) = @_;

    $name  = lc( $self->canonicalize_name( $name ) );
    $type  = lc( $type );
    $class = lc( $class );

    foreach my $rr ( $p->answer ) {
        my $rrname  = lc( $self->canonicalize_name( $rr->name ) );
        my $rrtype  = lc( $rr->type );
        my $rrclass = lc( $rr->class );

        printf STDERR "matches: %s => %s, %s => %s, %s => %s\n", $rrname, $name, $rrtype, $type, $rrclass, $class
          if $self->{debug};
        if ( $rrname eq $name and ( $rrtype eq $type or $type eq 'any' ) and ( $rrclass eq $class or $class eq 'any' ) ) {
            print STDERR "matches: Found.\n" if $self->{debug};
            return 1;
        }
    }

    print STDERR "matches: Not found.\n" if $self->{debug};
    return;
}

sub matching_labels {
    my $self = shift;
    my ( $n1, $n2 ) = @_;

    my @n1 = reverse split /\./, $n1;
    my @n2 = reverse split /\./, $n2;
    my $count = 0;

    while ( @n1 and @n2 ) {
        my $i = shift @n1;
        my $j = shift @n2;

        if ( $i eq $j ) {
            $count += 1;
        }
        else {
            last;
        }
    }

    return $count;
}

1;

=head1 NAME

DNSCheck::Lookup::Resolver - a recursive DNS resolver for DNSCheck

=head1 DESCRIPTION

This module does recursive lookups, and is heavily used by L<DNSCheck::Lookup::DNS>. 

=head1 PUBLIC METHODS

=over

=item ->new($parent)

Creates and configures a new resolver object. The parent object should be a
L<DNSCheck> object, and it will be used to find DNS resolver configuration
information.

=item ->get($name, $type, $class, @nameservers)

Send a DNS query to specified servers.

=item ->recurse($name, $type, [$class])

Do a recursive query. If the class is not specified, it defaults to IN.

=back

=head1 INTERNAL METHODS

=over

=item ->get_preload_data()

Class method. Does a recursive global NS lookup for the root zone, using the 
system paramters, and returns a reference to a nested hash stucture suitable 
for use as an object cache.

=item ->add_fake_glue()

Add fake glue for an undelegated test.

=item ->add_fake_ds()

Add a fake DS record for en undelegated test.

=item ->cache()

Return a reference to the object's name cache.

=item ->canonicalize_name($name)

Return the given name in its canonical form, with a trailing dot.

=item ->resolver()

Returns the underlying L<Net::DNS::Resolver> object that's used to send queries 
to nameservers.

=item ->cdflag()
=item ->dnssec()
=item ->recursion()
=item ->errorstring()

These four methods simply proxy to the underlying resolver object.

=item ->fake_ns_packet()

Create an artificial response packet to an NS query.

=item ->fake_ds_packet()

Create an artificial response packet to a DS query.

=item ->fake_packet()

Create an artificial response packet to an A, AAAA or NS query.

=item ->faked_zone($zone)

Return nameserver names for the given zone if fake glue has been added for it, 
or C<undefined> if not.

=item ->faked_zones()

Return a list of the names of all zones we have fake glue data for.

=item ->highest_known_ns()

Return the nearest ancestor zone we have in cache for the given zone name.

=item ->matches($packet, $name, $type, $class)

Check if the given L<Net::DNS::Packet> contains any records matching the given 
name, type and class.

=item ->matching_labels($name1, $name2)

Count the number of matching labels in the two given names.

=item ->names_to_ips(@namelist)

Return a list of IP addresses for the given names, doing recursive lookups for them.

=item ->simple_names_to_ips()

Return a list of IP addresses for the given names, only looking at what is 
already in the object's cache.

=item ->remember($packet)

Add data from the given response packet to the object's cache.

=item ->strip_label($name)

Return a name that's one label shorter than the given name, except if the given 
name is the root, in which case the root is returned.

=item ->parent()
=item ->config()
=item ->logger()

These three are the same as in all other DNSCheck classes.

=item ->times()

Return a reference to the nested hash structure holding nameserver response 
time data.

=item ->trace($domain)

Return a list describing the recursion chain that led from the root to the given domain.

=back

=cut
