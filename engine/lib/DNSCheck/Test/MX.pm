#!/usr/bin/perl

package DNSCheck::Test::MX;

require 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';

######################################################################

sub test {
    my $self   = shift;
    my $parent = $self->parent;
    my $zone   = shift;

    return 0 unless $parent->config->should_run;

    my $logger = $parent->logger;
    my $errors = 0;

    $logger->module_stack_push();
    $logger->auto( "MX:BEGIN" );

    # REQUIRE: MX or A must exist for domain
    my @mailhosts = $parent->dns->find_mx( $zone );

    if ( @mailhosts ) {
        $logger->auto( "MX:HOSTS", join( ",", @mailhosts ) );
    }

    if ( defined( $zone ) and scalar( @mailhosts ) == grep { m/$zone$/ } @mailhosts ) {
        $logger->auto( "MX:ALL_HOSTS_IN_ZONE", $zone );
    }

    unless ( scalar @mailhosts ) {
        $errors += $logger->auto( "MX:RECORDS_NOT_FOUND", $zone );
        goto DONE;
    }

    # REQUIRE: MX points to valid hostname
    foreach my $hostname ( @mailhosts ) {
        if ( $parent->host->test( $hostname ) > 0 ) {
            $errors += $logger->auto( "MX:HOST_ERROR", $hostname );
            next;
        }

        my $ipv4 = $parent->dns->query_resolver( $hostname, "IN", "A" );
        my $ipv6 = $parent->dns->query_resolver( $hostname, "IN", "AAAA" );

        # REQUIRE: Warn if a mail exchanger is reachable by IPv6 only
        if (   ( $ipv4 && scalar( $ipv4->answer ) == 0 )
            && ( $ipv6 && scalar( $ipv6->answer ) > 0 ) )
        {
            $errors += $logger->auto( "MX:IPV6_ONLY", $hostname );
        }

        # Store the addresses found
        if ($ipv4 && scalar( $ipv4->answer ) > 0) {
            my @addr = map { $_->address } $ipv4->answer;
            $logger->auto( "MX:V4_ADDR", $zone, $hostname,
                    join(",", @addr));
        }
        if ($ipv6 && scalar( $ipv6->answer ) > 0) {
            my @addr = map { $_->address } $ipv6->answer;
            $logger->auto( "MX:V6_ADDR", $zone, $hostname,
                    join(",", @addr));
        }
    }

  DONE:
    $logger->auto( "MX:END");
    $logger->module_stack_pop();

    return $errors;
}

1;

__END__


=head1 NAME

DNSCheck::Test::MX - Discovers and tests MX records

=head1 DESCRIPTION

Test MX records for a given name

=over 4

=item *
An MX or A record must exist for the domain name

=item *
The MX record must point to a valid hostname.

=item *
Discovers if the hostname has v4 or v6 addresses

=back

=head1 METHODS

=head2 test(I<zone>);

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>, L<DNSCheck::Test::Host>

=cut
