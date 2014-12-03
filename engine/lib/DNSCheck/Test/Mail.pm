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

package DNSCheck::Test::Mail;

require 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';

use Mail::RFC822::Address qw[valid];

######################################################################

sub test {
    my $self   = shift;
    my $parent = $self->parent;
    my $email  = shift;
    my $zone   = shift;

    return 0 unless $parent->config->should_run;

    my $logger = $parent->logger;
    my $errors = 0;

    $logger->module_stack_push();
    $logger->auto( "MAIL:BEGIN", $email );

    # Slightly less broken than just using split()
    my ( $localpart, $domain ) = $email =~ m|^ (.+) @ ([-_.a-z0-9]+) $|ix;

    unless ( valid( $email ) ) {
        $errors += $logger->auto( "MAIL:ADDRESS_SYNTAX", $email );
        goto DONE;
    }

    # REQUIRE: MX or A must exist for domain
    my @mailhosts = $parent->dns->find_mx( $domain );

    if ( @mailhosts ) {
        $logger->auto( "MAIL:MAIL_EXCHANGER", $email, join( ",", @mailhosts ));
    }

    if ( defined( $zone ) and scalar( @mailhosts ) == grep { m/$zone$/ } @mailhosts ) {
        $logger->auto( "MAIL:ALL_MX_IN_ZONE", $email, $zone );
    }

    unless ( scalar @mailhosts ) {
        $errors += $logger->auto( "MAIL:DOMAIN_NOT_FOUND", $domain );
        goto DONE;
    }

    # REQUIRE: MX points to valid hostname
    foreach my $hostname ( @mailhosts ) {
        if ( $parent->host->test( $hostname ) > 0 ) {
            $errors += $logger->auto( "MAIL:HOST_ERROR", $hostname );
            next;
        }

        my $ipv4 = $parent->dns->query_resolver( $hostname, "IN", "A" );
        my $ipv6 = $parent->dns->query_resolver( $hostname, "IN", "AAAA" );

        # REQUIRE: Warn if a mail exchanger is reachable by IPv6 only
        if (   ( $ipv4 && scalar( $ipv4->answer ) == 0 )
            && ( $ipv6 && scalar( $ipv6->answer ) > 0 ) )
        {
            $errors += $logger->auto( "MAIL:IPV6_ONLY", $hostname );
        }
    }

  DONE:
    $logger->auto( "MAIL:END", $email );
    $logger->module_stack_pop();

    return $errors;
}

1;

__END__


=head1 NAME

DNSCheck::Test::Mail - Test email addresses

=head1 DESCRIPTION

Test email address. The following tests are made:

=over 4

=item *
An MX or A record must exist for the domain name of the email address.

=item *
The MX record must point to a valid hostname.

=back

=head1 METHODS

=head2 test(I<emailaddress>, [I<zone>]);

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>, L<DNSCheck::Test::Host>

=cut
