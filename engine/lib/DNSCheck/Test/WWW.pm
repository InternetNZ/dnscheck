#!/usr/bin/perl

# DNSCheck::Test::WWW
# Author: Sebastian Castro <sebastian@nzrs.net.nz>
# Description: Tests <www.$domain> and <$domain> for A/AAAA addresses
# listening on port 80 (HTTP) and port 443 (HTTPS).
#
######################################################################

package DNSCheck::Test::WWW;

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

    # XXX Confirm which flag should exist
    return 0 unless $parent->config->should_run;

    my $logger = $parent->logger;
    my $errors = 0;

    $self->zone( $zone );

    # XXX What is this for?
    my $packet;

    $logger->module_stack_push();
    $logger->auto( "WWW:BEGIN", $zone );

    # Use some standard destinations for web
    foreach my $web_host ( 'www.' . $zone, $zone ) {
        my $addr_set = $parent->dns->find_addresses_with_ttl( $web_host, $self->qclass );
        $self->webhost( $web_host );
        # $errors += $self->_test_ip( @addresses );
        # Just log the addresses found at the moment
        $logger->auto( "WWW:SERVER_ADDR_4", $zone, $web_host,
            join(",", @{$addr_set->{4}{'addr'}}), $addr_set->{4}{'ttl'})
            if (defined $addr_set->{4});
        $logger->auto( "WWW:SERVER_ADDR_6", $zone, $web_host,
            join(",", @{$addr_set->{6}{'addr'}}), $addr_set->{6}{'ttl'})
            if (defined $addr_set->{6});
    }

  DONE:
    $logger->auto( "WWW:END", $zone );
    $logger->module_stack_pop();

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

sub webhost {
    my $self    = shift;
    my $webhost = shift;

    if ( defined( $webhost ) ) {
        $self->{webhost} = $webhost;
    }

    return $self->{webhost};
}


################################################################
# Individual tests
################################################################

sub web_http {
    my $self       = shift;
    my $address    = shift;
    my $webserver  = shift // $self->webserver;

    return 0 unless $self->parent->config->should_run;

    $self->logger->auto( "WEBSERVER:TESTING_HTTP", $webserver, $address );

    my $response = $self->parent->web->request( 'http', $webserver,
    $address );
    if ($response) {
        return $self->logger->auto( "WEBSERVER:HTTP_OK", $webserver, $address, $response->code );
    }
    else {
        return $self->logger->auto( "WEBSERVER:NO_HTTP", $webserver, $address );
    }
}


1;

__END__


=head1 NAME

DNSCheck::Test::WWW - Test WWW for a zone

=head1 DESCRIPTION

Test a pre-defined set of hosts (www.$domain, $domain) for web service
(HTTP, HTTPS) on all addresses found. 

=head1 METHODS

=over

=item ->new($parent, $zone, $nameserver)

Create a new test object, and optionally set the zone and nameserver name that
will be tested. If those two are set, the values will be used as defaults for
many other methods.

=item ->test($zone);

Perform the default set of tests for a zone. Currently only fetches
addresses for $zone and www.$zone

=item ->zone($zone)

Get or set the default zone for this object.

=back

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>, L<DNSCheck::Test::Host>

=cut
