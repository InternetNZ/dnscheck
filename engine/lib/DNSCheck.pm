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

package DNSCheck;

require 5.010001;    # 5.10.1
use warnings;
use strict;
use utf8;

use DBI;
use Carp;
use List::Util qw[reduce max min];
use Net::DNS;
use Net::DNS::RR;
use Storable qw[thaw];
use MIME::Base64;

use DNSCheck::Config;
use DNSCheck::Test::Common;
use DNSCheck::Test::Host;
use DNSCheck::Test::Address;
use DNSCheck::Test::SOA;
use DNSCheck::Test::Zone;
use DNSCheck::Test::Connectivity;
use DNSCheck::Test::Consistency;
use DNSCheck::Test::Delegation;
use DNSCheck::Test::Nameserver;
use DNSCheck::Test::DNSSEC;
use DNSCheck::Test::Mail;
use DNSCheck::Test::WWW;
use DNSCheck::Lookup::DNS;
use DNSCheck::Lookup::Resolver;
use DNSCheck::Lookup::ASN;
use DNSCheck::Logger;

our $VERSION = "1.5.0";

######################################################################

sub new {
    my $proto = shift;
    my $class = ref( $proto ) || $proto;
    my $self  = {};
    bless $self, $class;

    my $config_args = shift;
    if ( $config_args->{with_config_object} ) {
        $self->{config} = $config_args->{with_config_object};
    }
    else {
        $self->{config} = DNSCheck::Config->new( %{$config_args} );
        if ( my $b64root = $self->{config}->get( 'dns' )->{rootdata} ) {
            $self->config->put( 'root_zone_data', thaw( decode_base64( $b64root ) ) );
        }
        else {
            $self->config->put( 'root_zone_data', DNSCheck::Lookup::Resolver->get_preload_data( $config_args->{rootsource} ) );
        }
    }

    return $self;
}

######################################################################

sub flush {
    my $self = shift;

    # Dump the DNS cache.
    $self->{dns}->flush();

    # Dump all cached test objects.
    $self->{test_zone}         = undef;
    $self->{test_host}         = undef;
    $self->{test_address}      = undef;
    $self->{test_soa}          = undef;
    $self->{test_connectivity} = undef;
    $self->{test_consistency}  = undef;
    $self->{test_delegation}   = undef;
    $self->{test_nameserver}   = undef;
    $self->{test_www}          = undef;
    $self->{test_dnssec}       = undef;
    $self->{test_mail}         = undef;
    $self->{faked}             = [];

    # should the ASN cache be flushed as well?
    #$self->{context}->{asn}->flush();

    return;
}

######################################################################

sub add_fake_glue {
    my $self    = shift;
    my $zone    = shift;
    my $ns_name = shift;
    my $ns_ip   = shift;

    $self->{faked} = 1;

    unless ( defined( $ns_ip ) ) {
        my @ip = $self->dns->find_addresses( $ns_name, 'IN' );
        if ( @ip == 0 ) {
            $self->logger->auto( "FAKEGLUE:NO_ADDRESS", $ns_name );
            return;
        }
        else {
            $self->resolver->add_fake_glue( $zone, $ns_name, $_ ) for @ip;
        }
    }
    else {
        unless ( $self->resolver->add_fake_glue( $zone, $ns_name, $ns_ip ) ) {
            $self->logger->auto( 'FAKEGLUE:BROKEN_INFO', $ns_ip, $ns_name );
        }
    }

    return 1;
}

sub add_fake_ds {
    my $self = shift;
    my $data = shift;

    $self->{faked} = 1;

    my $ds = eval { Net::DNS::RR->new( $data ) };
    unless ( $ds and $ds->type eq 'DS' ) {
        $self->logger->auto( 'FAKEGLUE:MALFORMED_DS', $data );
        return;
    }

    $self->resolver->add_fake_ds( $ds );

    return 1;
}

sub undelegated_test {
    my $self = shift;

    return $self->{faked};
}

######################################################################

sub logger {
    my $self = shift;

    unless ( defined( $self->{logger} ) ) {
        $self->{logger} = DNSCheck::Logger->new( $self );
    }

    return $self->{logger};
}

sub dns {
    my $self = shift;

    unless ( defined( $self->{dns} ) ) {
        $self->{dns} = DNSCheck::Lookup::DNS->new( $self );
    }

    return $self->{dns};
}

sub resolver {
    my $self = shift;

    unless ( defined( $self->{resolver} ) ) {
        $self->{resolver} = DNSCheck::Lookup::Resolver->new( $self );
    }

    return $self->{resolver};
}

sub asn {
    my $self = shift;

    unless ( defined( $self->{asn} ) ) {
        $self->{asn} = DNSCheck::Lookup::ASN->new( $self );
    }

    return $self->{asn};
}

sub web {
    my $self = shift;

    unless ( defined( $self->{web} ) ) {
        $self->{web} = DNSCheck::Agent::Web->new( $self );
    }

    return $self->{web};
}

sub config {
    my $self = shift;
    return $self->{config};
}

sub dbh {
    my $self  = shift;
    my $tries = 0;
    my $dbh;

    unless ( defined( $self->config->get( "dbi" ) ) ) {
        return;
    }

    unless ( defined( $self->{"dbh"} ) && $self->{"dbh"}->ping ) {
        until ( defined( $dbh ) or ( $tries > 5 ) ) {

            # We don't care if config variables are unset. Just try to
            # connect using what we were given and see if it works.
            ## no critic (TestingAndDebugging::ProhibitNoWarnings)
            no warnings 'uninitialized';
            $tries += 1;
            my $conf = $self->config->get( "dbi" );
            my $dsn = sprintf( "DBI:mysql:database=%s;hostname=%s;port=%s", $conf->{"database"}, $conf->{"host"}, $conf->{"port"} );

            eval { $dbh = DBI->connect( $dsn, $conf->{"user"}, $conf->{"password"}, { RaiseError => 1, AutoCommit => 1, PrintError => 0 } ); };
            if ( $@ ) {
                carp "Failed to connect to database: $@";
            }
        }

        if ( defined( $dbh ) ) {
            $self->{"dbh"} = $dbh;
        }
        else {
            croak "Cannot connect to database.";
        }
    }

    return $self->{"dbh"};
}

sub _stddev {
    my @values = @_;

    my $avg = ( reduce { $a + $b } @values ) / scalar( @values );
    my $dev = reduce { $a + $b } map { $_ * $_ } map { $_ - $avg } @values;

    return sqrt( $dev / scalar( @values ) );
}

sub log_nameserver_times {
    ## no critic (TestingAndDebugging::ProhibitNoWarnings)
    no warnings 'uninitialized';

    my $self = shift;
    my $zone = shift;
    my %t    = %{ $self->resolver->times };

    my %ns = map { $_ => 1 } ( @{ $self->dns->{nameservers}{$zone}{'IN'}{'ipv4'} }, @{ $self->dns->{nameservers}{$zone}{'IN'}{'ipv6'} }, );

    while ( my ( $k, $v ) = each %t ) {
        next unless $ns{$k};
        my $sum = reduce { $a + $b } @$v;
        $self->logger->auto( 'NSTIME:AVERAGE', $zone, $k, scalar( @$v ), sprintf( '%0.3f', 1000 * ( $sum / @$v ) ), sprintf( '%0.3f', 1000 * min( @$v ) ), sprintf( '%0.3f', 1000 * max( @$v ) ), sprintf( '%0.3f', 1000 * _stddev( @$v ) ), );
    }

    return;
}

######################################################################
# Test objects
######################################################################

sub zone {
    my $self = shift;
    unless ( defined( $self->{test_zone} ) ) {
        $self->{test_zone} = DNSCheck::Test::Zone->new( $self );
    }

    return $self->{test_zone};
}

sub host {
    my $self = shift;

    unless ( defined( $self->{test_host} ) ) {
        $self->{test_host} = DNSCheck::Test::Host->new( $self );
    }

    return $self->{test_host};
}

sub address {
    my $self = shift;

    unless ( defined( $self->{test_address} ) ) {
        $self->{test_address} = DNSCheck::Test::Address->new( $self );
    }

    return $self->{test_address};
}

sub soa {
    my $self = shift;

    unless ( defined( $self->{test_soa} ) ) {
        $self->{test_soa} = DNSCheck::Test::SOA->new( $self );
    }

    return $self->{test_soa};
}

sub connectivity {
    my $self = shift;

    unless ( defined( $self->{test_connectivity} ) ) {
        $self->{test_connectivity} = DNSCheck::Test::Connectivity->new( $self );
    }

    return $self->{test_connectivity};
}

sub consistency {
    my $self = shift;

    unless ( defined( $self->{test_consistency} ) ) {
        $self->{test_consistency} = DNSCheck::Test::Consistency->new( $self );
    }

    return $self->{test_consistency};
}

sub delegation {
    my $self = shift;

    unless ( defined( $self->{test_delegation} ) ) {
        $self->{test_delegation} = DNSCheck::Test::Delegation->new( $self );
    }

    return $self->{test_delegation};
}

sub nameserver {
    my $self = shift;

    unless ( defined( $self->{test_nameserver} ) ) {
        $self->{test_nameserver} = DNSCheck::Test::Nameserver->new( $self );
    }

    return $self->{test_nameserver};
}

sub dnssec {
    my $self = shift;

    unless ( defined( $self->{test_dnssec} ) ) {
        $self->{test_dnssec} = DNSCheck::Test::DNSSEC->new( $self );
    }

    return $self->{test_dnssec};
}

sub mail {
    my $self = shift;

    unless ( defined( $self->{test_mail} ) ) {
        $self->{test_mail} = DNSCheck::Test::Mail->new( $self );
    }

    return $self->{test_mail};
}

sub www {
    my $self = shift;

    unless ( defined( $self->{test_www} ) ) {
        $self->{test_www} = DNSCheck::Test::WWW->new( $self );
    }

    return $self->{test_www};
}

######################################################################

1;

__END__


=head1 NAME

DNSCheck - DNS Check Tools

=head1 DESCRIPTION

This module provides the external interface to the actual tests in the
DNSCheck system.

=head1 METHODS

=over

=item ->new($confighashref);

C<confighashref> is a reference to a hash holding configuration keys.
They will be blindly used to create a L<DNSCheck::Config> object,
unless one key is C<with_config_object>. If there is such a key, its
value will be used as the L<DNSCheck::Config> object. No check to see
if it actually I<is> such an object will be done, so anything that
responds to the right methods can be used.

Providing a pre-created config object can be useful when creating and
discarding a large number of L<DNSCheck> objects, since config object
creation normally stands for the majority of the time it takes to
create such an object. Creating the config object once and then
providing it to every L<DNSCheck> may save considerable time in the
long run. An example if this use can be found in the
C<dnscheck-dispatcher> application.

=item ->flush()

Flush the internal DNS cache.

=item ->logger()

Return the logger object. It is of type L<DNSCheck::Logger>.

=item ->dns()

Return the DNS lookup object. It is of type L<DNSCeck::Lookup::DNS>.

=item ->resolver()

Returns the actual recursing resolver object.

=item ->asn()

Return the ASN lookup object. It is of type L<DNSCheck::Lookup::ASN>.

=item ->config()

Return the config object. It will be of type L<DNSCheck::Config> unless
something different was given to C<new> as described above.

=item ->dbh()

Return a live database connection (L<DBI>) object, if database access is
configured. If not, returns C<undef>. If a database connection is configured,
it should point at a database with the dnscheck schema loaded, or the first
sub-module here to try and use the database will throw an exception and cause
the script to die.

This method uses L<DBI::ping()> to determine if a connection is alive
or not, so make sure to use a DBI adapter where that isn't a null
operation (as it used to be in older versions of L<DBD::mysql>). Also,
since the included database schema assumes that the database is MySQL,
this method will try to connect to the server five times before it
gives up and dies.

=item ->add_fake_glue($zone, $nsname, [$nsip])

Add an item of "fake" glue data. For the given zone, the provided information
will be used instead of what can be found live in DNS (if any). If an IP
address is provided, it will be used. If not, an attempt to look up addresses
for the name will be made. If that attempt fails, the name will be ignored.

=item ->undelegated_test()

This method returns true of any "fake" glue information has been provided.

=item ->log_nameserver_times($zone)

Extracts response timing data for the given zone's nameservers from the 
resolver object and adds the information as log messages. Has to be called 
after a test is run, since before there is obviously no data to extract.

=item ->zone()

=item ->host()

=item ->address()

=item ->soa()

=item ->connectivity()

=item ->consistency()

=item ->delegation()

=item ->nameserver()

=item ->dnssec()

=item ->mail()

=item ->www()

These eleven methods all return properly configured objects of the
respective test classes. For more details on how to use the objects,
see the documentation on the modules in question. Generally, though,
they have a main entry method called C<test> that runs all available
tests with the arguments given.

The objects returned are created on first request and cached for
future use. Use the C<flush()> method to discard the existing objects,
so that new ones will be created on next request.

=back

=head1 EXAMPLES

   use DNSCheck;
   
   my $dc = DNSCheck->new;
   $dc->zone->test("iis.se");
   $dc->logger->dump;
   
=head1 KNOWN PROBLEMS

=over

=item Limited DNSSEC signature validity span.

If DNSCheck is run with a perl interpreter that uses 32-bit integers, it will
erroneously report DNSSEC signatures with expire dates after 19 Jan 2038 as
being invalid.

=back

=head1 SEE ALSO

L<DNSCheck::Config.pm>, L<DNSCheck::Locale.pm>,
L<DNSCheck::Logger.pm>, L<DNSCheck::Lookup::ASN.pm>,
L<DNSCheck::Lookup::DNS.pm>, L<DNSCheck::Test::Address.pm>,
L<DNSCheck::Test::Common.pm>, L<DNSCheck::Test::Connectivity.pm>,
L<DNSCheck::Test::Consistency.pm>, L<DNSCheck::Test::Delegation.pm>,
L<DNSCheck::Test::DNSSEC.pm>, L<DNSCheck::Test::Host.pm>,
L<DNSCheck::Test::Mail.pm>, L<DNSCheck::Test::Nameserver.pm>,
L<DNSCheck::Test::SOA.pm>, L<DNSCheck::Test::Zone.pm>,
L<DNSCheck::Test::WWW.pm>

=cut
