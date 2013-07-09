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

package DNSCheck::Test::Zone;

use 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';

use List::MoreUtils qw[distinct];

######################################################################

sub test {
    my $self    = shift;
    my $zone    = shift;
    my $history = shift;

    my $parent = $self->parent;
    my $qclass = $self->qclass;
    my $logger = $parent->logger;

    return 0 unless $parent->config->should_run;

    $logger->logname( $zone );

    $logger->module_stack_push();
    ## no critic (Modules::RequireExplicitInclusion)
    $logger->auto( "ZONE:BEGIN", $zone, $DNSCheck::VERSION );

    if ( $parent->host->host_syntax( $zone ) ) {
        $logger->auto( 'ZONE:INVALID_NAME', $zone );
        goto DONE;
    }

    my ( $errors, $testable ) = $parent->delegation->test( $zone, $history );

    unless ( $testable ) {
        $logger->auto( "ZONE:FATAL_DELEGATION", $zone );
        goto DONE;
    }

    my @ns_at_child = $parent->dns->get_nameservers_at_child( $zone, $qclass );
    my @ns_at_parent = $parent->dns->get_nameservers_at_parent( $zone, $qclass );

    unless ( $ns_at_child[0] and $ns_at_parent[0]) {

        # This shouldn't happen because get_nameservers_at_child was also
        # called in DNSCheck::Test::Delegation->test
        $logger->auto( "ZONE:FATAL_NO_CHILD_NS", $zone );
        goto DONE;
    }

    foreach my $ns ( distinct @ns_at_child, @ns_at_parent ) {
        $errors += $parent->nameserver->test( $zone, $ns );
    }

    $errors += $parent->consistency->test( $zone );
    $errors += $parent->soa->test( $zone );
    $errors += $parent->connectivity->test( $zone );
    $errors += $parent->www->test( $zone );
    $errors += $parent->dnssec->test( $zone );

  DONE:
    $parent->log_nameserver_times($zone);
    $logger->auto( "ZONE:END", $zone );
    $logger->module_stack_pop();

    return $errors;
}

1;

__END__


=head1 NAME

DNSCheck::Test::Zone - Test a zone

=head1 DESCRIPTION

Test a zone using all DNSCheck modules, or test an undelegated zone at given
servers with all tests that make sense. The results of all tests will end up
in the logger object.

=head1 METHODS

=over

=item ->new(I<$parent>)

This method is not meant to be used directly. Use L<DNSCheck::zone> instead.

=item ->test(I<zone>, [I<$history>])

Run the standard set of tests on the given domain, possibly also giving a
reference to an array with the names of nameservers that used to be
authoritative for the zone.

=back

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>, L<DNSCheck::Test::Delegation>,
L<DNSCheck::Test::Nameserver>, L<DNSCheck::Test::Consistency>,
L<DNSCheck::Test::SOA>, L<DNSCheck::Test::Connectivity>,
L<DNSCheck::Test::DNSSEC>

=cut
