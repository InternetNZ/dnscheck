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

package DNSCheck::Test::DNSSEC;

use 5.010001;
use warnings;
use strict;
use utf8;

use base 'DNSCheck::Test::Common';

use Net::DNS 0.59;
use Net::DNS::SEC 0.16;
use Date::Parse;
use POSIX qw(strftime);

# http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
sub algorithm_name {
    my $aid   = shift;
    my %names = (
        0   => 'Reserved (0)',
        1   => 'RSA/MD5', # deprecated
        2   => 'Diffie-Hellman',
        3   => 'DSA/SHA1',
        4   => 'Reserved (ECC)',
        5   => 'RSA/SHA-1',
        6   => 'DSA-NSEC3-SHA1',
        7   => 'RSA-NSEC3-SHA1 ',
        8   => 'RSA/SHA-256',
        9   => 'Unassigned (9)',
        10  => 'RSA/SHA-512',
        11  => 'Unassigned (11)',
        12  => 'GOST R 34.10-2001',
        13  => 'ECDSA Curve P-256 with SHA-256',
        14  => 'ECDSA Curve P-384 with SHA-384',
        15  => 'Ed25519',
        16  => 'Ed448',
        252 => 'Reserved (Indirect keys)',
        253 => 'Private algorithm (domain name)',
        254 => 'Private algorithm (OID)',
        255 => 'Reserved'
    );

    if ( $names{$aid} ) {
        return $names{$aid};
    }
    elsif ( $aid >= 17 and $aid <= 122 ) {
        return "Unassigned ($aid)";
    }
    elsif ( $aid >= 123 and $aid <= 251 ) {
        return "Reserved ($aid)";
    }
    else {
        return "Strange algorithm id ($aid)";
    }
}

######################################################################

sub test {
    my $self   = shift;
    my $parent = $self->parent;
    my $zone   = shift;

    return 0 unless $parent->config->should_run;

    my $qclass = $self->qclass;
    my $logger = $parent->logger;
    my $errors = 0;
    my $flags  = { transport => "tcp", dnssec => 1, aaonly => 1 };
    my $packet;

    my $ds;
    my $dnskey;

    my $child_errors;
    my $child_result;
    my $parent_errors;

    $logger->module_stack_push();
    $logger->auto( "DNSSEC:BEGIN", $zone );

    my $faked_zone = $self->parent->resolver->faked_zone( $zone );

    # Query parent for DS
    # if DS is found at parent, the child must be signed
    $logger->auto( "DNSSEC:CHECKING_DS_AT_PARENT", $zone );
    $packet = $parent->dns->query_parent_nocache( $zone, $zone, $qclass, "DS", $flags );
    unless ( $packet and $packet->header->rcode eq 'NXDOMAIN' and $faked_zone ) {
        $ds = _dissect( $packet, "DS" );
        if ( $ds && $#{ $ds->{DS} } >= 0 ) {
            $logger->auto( "DNSSEC:DS_FOUND", $zone );
        }
        else {
            $logger->auto( "DNSSEC:NO_DS_FOUND", $zone );
        }
    }

    # Query child for DNSKEY
    # if DNSKEY is found at child, the child is probably running DNSSEC
    $logger->auto( "DNSSEC:CHECKING_DNSKEY_AT_CHILD", $zone );

    # Loop over all children. Ask for DNSKEY with DNSSEC enabled.
    # Check for DNSKEY+RRSIG. Let through the best one we find.
    # Warn for inconsistent replies.
    my @nsc;
    my $v4nsc;
    $v4nsc = $parent->dns->get_nameservers_ipv4( $zone, $qclass )
      if $self->config->get( "net" )->{ipv4};
    push @nsc, @$v4nsc if $v4nsc;
    my $v6nsc;
    $v6nsc = $parent->dns->get_nameservers_ipv6( $zone, $qclass )
      if $self->config->get( "net" )->{ipv6};
    push @nsc, @$v6nsc if $v6nsc;

    my %extra;
    my $good_packet;
    foreach my $childns ( @nsc ) {
        $packet = $parent->dns->query_explicit( $zone, $qclass, 'DNSKEY', $childns, $flags );
        next unless ( $packet and scalar( $packet->answer ) > 0 );
        my $tmp = _dissect( $packet, 'DNSKEY' );
        if (    $tmp
            and ( $tmp->{DNSKEY} and @{ $tmp->{DNSKEY} } > 0 )
            and ( $tmp->{RRSIG}  and @{ $tmp->{RRSIG} } > 0 ) )
        {
            $logger->auto( 'DNSSEC:EXTRA_PROCESSING', $childns );
            $extra{yes} += 1;
            $good_packet = $packet;
        }
        else {
            $logger->auto( 'DNSSEC:NO_EXTRA_PROCESSING', $childns );
            $extra{no} += 1;
        }
    }

    if ( $extra{yes} and $extra{no} ) {
        $logger->auto( 'DNSSEC:INCONSISTENT_EXTRA_PROCESSING', $zone );
    }
    else {
        $logger->auto( 'DNSSEC:CONSISTENT_EXTRA_PROCESSING', $zone );
    }

    $packet = $good_packet || $packet;

    # End of all-child processing.

    # NSEC or NSEC3 presence test
    my $nsecp = $parent->dns->query_child_nocache($zone, 'xn--example.' . $zone, $qclass, 'A', $flags);
    my $nsec_rr;
    ($nsec_rr) = grep {$_->type eq 'NSEC' or $_->type eq 'NSEC3'} $nsecp->authority if $nsecp;
    if ($nsec_rr) {
        $logger->auto('DNSSEC:NSEC_FOUND', $zone, $nsec_rr->type);
    } else {
        $logger->auto('DNSSEC:NSEC_NOT_FOUND', $zone);
    }

    # NESC3 parameter test
    my $nsec3p = $parent->dns->query_child($zone, $zone, $qclass, 'NSEC3PARAM');

    my $nsec3param_rr;
    my $iterations = $parent->config->get( "params" )->{'NSEC3:ITERATIONS'} || 150;
    ($nsec3param_rr) = grep {$_->type eq 'NSEC3PARAM'} $nsec3p->answer if $nsec3p;
    if ($nsec3param_rr) {
        $logger->auto( 'DNSSEC:NSEC3PARAM_FOUND', $zone);
        if ($nsec3param_rr->iterations > $iterations) {
            $logger->auto('DNSSEC:NSEC3_TOO_MANY_ITERATIONS', $zone, $nsec3param_rr->iterations, $iterations);
        } else {
            $logger->auto('DNSSEC:NSEC3_ITERATIONS_OK', $zone, $nsec3param_rr->iterations, $iterations);
        }
    } else {
        $logger->auto( 'DNSSEC:NSEC3PARAM_NOT_FOUND', $zone);
    }

    $dnskey = _dissect( $packet, "DNSKEY" );

    # TODO: check that the DNSKEY protocol field is equal to 3
    if ( $dnskey && $#{ $dnskey->{DNSKEY} } >= 0 ) {
        $logger->auto( "DNSSEC:DNSKEY_FOUND", $zone );
    }
    else {
        $logger->auto( "DNSSEC:DNSKEY_NOT_FOUND", $zone );
    }

    # Determine security status
    $logger->auto( "DNSSEC:DETERMINE_SECURITY_STATUS", $zone );
    if ( $ds ) {
        if ( $dnskey ) {
            ## DS at parent, DNSKEY at child
            $logger->auto( "DNSSEC:CONSISTENT_SECURITY", $zone );
        }
        else {
            ## DS at parent, but no DNSKEY at child
            $errors += $logger->auto( "DNSSEC:INCONSISTENT_SECURITY", $zone );
            goto DONE;
        }
    }
    else {
        if ( $dnskey ) {
            ## DNSKEY at child, no DS at parent
            # TODO: is this noteworthy?
        }
        else {
            ## No DNSKEY at child and no DS at parent
            # TODO: is this noteworthy?
        }
    }

    if ( !$dnskey ) {

        # Child has no DNSKEY, we're done
        $logger->auto( "DNSSEC:SKIPPED_NO_KEYS", $zone );
        goto DONE;
    }

    if ( not $ds and $dnskey and not $faked_zone ) {
        $errors += $logger->auto( "DNSSEC:MISSING_DS", $zone );
    }

    ( $child_errors, $child_result ) = _check_child( $parent, $zone, $dnskey );
    $errors += $child_errors;

    # Only check parent if we've found a DS at the parent
    if ( $ds ) {
        $parent_errors = _check_parent( $parent, $zone, $ds, $dnskey, $child_result );
        $errors += $parent_errors;
    }

  DONE:
    $logger->auto( "DNSSEC:END", $zone );
    $logger->module_stack_pop();
    return $errors;
}

######################################################################

sub _check_child {
    my $parent = shift;
    my $zone   = shift;
    my $dnskey = shift;

    my $qclass = $parent->config->get( "dns" )->{class};
    my $logger = $parent->logger;
    my $errors = 0;

    my $flags = { transport => "tcp", dnssec => 1 };

    my $packet;
    my %keyhash;
    my %result;

    my $mandatory_algorithm = 0;
    my $sep                 = 0;

    # initialize result set
    $result{rr}      = undef;
    $result{allkeys} = undef;
    $result{anchors} = ();
    $result{sep}     = ();

    $logger->auto( "DNSSEC:CHECKING_CHILD", $zone );

    foreach my $key ( @{ $dnskey->{DNSKEY} } ) {

        # REQUIRE: a DNSKEY SHOULD NOT be of type RSA/MD5
        if ( $key->algorithm == Net::DNS::SEC->algorithm( "RSAMD5" ) ) {
            $logger->auto( "DNSSEC:DNSKEY_ALGORITHM_NOT_RECOMMENDED", $zone, $key->keytag, "RSA/MD5" );
        }

        $logger->auto( 'DNSSEC:DNSKEY_ALGORITHM', $zone, $key->keytag, $key->algorithm, algorithm_name( $key->algorithm ) );
        $errors += check_algorithm( $logger, $key->algorithm );

        # REQUIRE: a DNSKEY used for RRSIGs MUST have protocol DNSSEC (3)
        if ( $key->protocol != 3 ) {
            $logger->auto( "DNSSEC:DNSKEY_SKIP_PROTOCOL", $zone, $key->keytag, $key->protocol );
            next;
        }

        # REQUIRE: a DNSKEY used for RRSIGs MUST be a zone key
        unless ( $key->flags & 0x0100 ) {
            $logger->auto( "DNSSEC:DNSKEY_SKIP_TYPE", $zone, $key->keytag );
            next;
        }

        $keyhash{ $key->keytag } = $key;

        if ( $key->is_sep ) {
            $logger->auto( "DNSSEC:DNSKEY_SEP", $zone, $key->keytag );
            push @{ $result{sep} }, $key->keytag;
            $sep++;
        }
    }

    # fill result set
    $result{rr} = \%keyhash;
    @{ $result{allkeys} } = keys %keyhash;

    unless ( $#{ $dnskey->{RRSIG} } >= 0 ) {

        $packet = $parent->dns->query_child_nocache( $zone, $zone, $qclass, "RRSIG", $flags );

        if ( $packet->header->rcode eq "NOERROR"
            and scalar( $packet->answer ) > 0 )
        {
            my $tmp = $packet->answerfrom;
            $errors += $logger->auto( "DNSSEC:ADDITIONAL_PROCESSING_BROKEN", $zone, ( $tmp ? $tmp : 'Unknown' ) );
        }
        else {
            $errors += $logger->auto( "DNSSEC:NO_SIGNATURES", $zone );
        }

        $logger->auto( "DNSSEC:CHILD_CHECK_ABORTED", $zone );

        goto DONE;
    }

    # REQUIRE: RRSIG(DNSKEY) MUST be valid and created by a valid DNSKEY
    my $valid_dnskey_signatures = 0;
    foreach my $sig ( @{ $dnskey->{RRSIG} } ) {
        my $valid = _check_signature( $parent, $zone, $sig, $dnskey->{DNSKEY}, $dnskey->{DNSKEY} );

        push @{ $result{anchors} }, $sig->keytag;

        if ( _count_in_list( $sig->keytag, $result{allkeys} ) == 1 ) {
            $valid_dnskey_signatures += $valid;

            $logger->auto( "DNSSEC:DNSKEY_SIGNATURE_OK", $zone, $sig->keytag );
        }
        else {
            $logger->auto( "DNSSEC:DNSKEY_SIGNER_UNPUBLISHED", $zone, $sig->keytag );
        }
    }
    if ( $valid_dnskey_signatures > 0 ) {
        ## Enough valid signatures over DNSKEY RRset
        $logger->auto( "DNSSEC:DNSKEY_VALID_SIGNATURES", $zone );
    }
    else {
        ## No valid signatures over the DNSKEY RRset
        $logger->auto( "DNSSEC:DNSKEY_NO_VALID_SIGNATURES", $zone );
    }

    # REQUIRE: RRSIG(SOA) MUST be valid and created by a valid DNSKEY
    $packet = $parent->dns->query_child_nocache( $zone, $zone, $qclass, "SOA", $flags );
    goto DONE unless ( $packet );
    my $soa = _dissect( $packet, "SOA" );
    my $valid_soa_signatures = 0;
    foreach my $sig ( @{ $soa->{RRSIG} } ) {
        my $valid = _check_signature( $parent, $zone, $sig, $dnskey->{DNSKEY}, $soa->{SOA} );

        push @{ $result{anchors} }, $sig->keytag;

        if ( _count_in_list( $sig->keytag, $result{allkeys} ) == 1 ) {
            $valid_soa_signatures += $valid;
            $logger->auto( "DNSSEC:SOA_SIGNATURE_OK", $zone, $sig->keytag );
        }
        else {
            $logger->auto( "DNSSEC:SOA_SIGNER_UNPUBLISHED", $zone, $sig->keytag );
        }
    }
    if ( $valid_soa_signatures > 0 ) {
        ## Enough valid signatures over SOA RRset
        $logger->auto( "DNSSEC:SOA_VALID_SIGNATURES", $zone );
    }
    else {
        ## No valid signatures over the SOA RRset
        $logger->auto( "DNSSEC:SOA_NO_VALID_SIGNATURES", $zone );
    }

  DONE:
    $logger->auto( "DNSSEC:CHILD_CHECKED", $zone );
    return ( $errors, \%result );
}

######################################################################

sub _check_parent {
    my $parent       = shift;
    my $zone         = shift;
    my $ds           = shift;
    my $dnskey       = shift;
    my $child_result = shift;

    my $qclass = $parent->config->get( "dns" )->{class};
    my $logger = $parent->logger;
    my $errors = 0;

    my $valid_ds_count      = 0;
    my $mandatory_algorithm = 0;

    $logger->auto( "DNSSEC:CHECKING_PARENT", $zone );

    foreach my $rr ( @{ $ds->{DS} } ) {

        my $ds_message = sprintf( "DS(%s/%d/%d/%d)", $zone, $rr->algorithm, $rr->digtype, $rr->keytag );

        $logger->auto( "DNSSEC:PARENT_DS", $zone, $ds_message );

        $logger->auto( 'DNSSEC:DS_ALGORITHM', $zone, $rr->keytag, $rr->algorithm, algorithm_name( $rr->algorithm ) );
        $errors += check_algorithm( $logger, $rr->algorithm );

        if ( $rr->algorithm == Net::DNS::SEC->algorithm( "RSAMD5" ) ) {
            $logger->auto( "DNSSEC:DS_ALGORITHM_MD5" );
        }

        # REQUIRE: the DS MUST point to a DNSKEY that is
        # signing the child's DNSKEY RRset
        my $crr = $child_result->{rr}{ $rr->keytag };
        my $cmsg;
        if ( $crr ) {
            $cmsg = sprintf( "DNSKEY(%s/%d/%d)", $zone, $crr->algorithm, $crr->keytag );
        }
        else {
            $cmsg = 'No key';
        }
        if (    _count_in_list( $rr->keytag, $child_result->{anchors} ) >= 1
            and $child_result->{rr}{ $rr->keytag }
            and $rr->verify( $child_result->{rr}{ $rr->keytag } ) )
        {
            ## DS refers to key signing the DNSKEY RRset
            $logger->auto( "DNSSEC:DS_KEYREF_OK", $ds_message, $cmsg );
            $valid_ds_count += 1;
        }
        else {
            ## DS refers to key not signing the DNSKEY RRset
            $logger->auto( "DNSSEC:DS_KEYREF_INVALID", $ds_message, $cmsg );
        }

        # REQUIRE: the DS MAY point to a SEP at the child
        if ( $#{ $child_result->{sep} } >= 0 ) {
            if ( _count_in_list( $rr->keytag, $child_result->{sep} ) > 0 ) {
                ## Child is using SEP and DS refers to a SEP
                $logger->auto( "DNSSEC:DS_TO_SEP", $zone, $ds_message );
            }
            else {
                ## Child is using SEP and DS refers to a non-SEP
                $logger->auto( "DNSSEC:DS_TO_NONSEP", $zone, $ds_message );
            }
        }
    }

    if ( $valid_ds_count == 0 ) {
        $errors += $logger->auto( 'DNSSEC:NO_VALID_DS', $zone );
    }

  DONE:
    $logger->auto( "DNSSEC:PARENT_CHECKED", $zone );
    return $errors;
}

######################################################################

sub _dissect {
    my $packet = shift;
    my $qtype  = shift;

    my %response = ();

    return unless ( $packet );

    foreach my $rr ( $packet->answer ) {
        if (    $rr->type eq "RRSIG"
            and $qtype ne "RRSIG"
            and $rr->typecovered eq $qtype )
        {
            push @{ $response{RRSIG} }, $rr;
            next;
        }

        if ( $rr->type eq $qtype ) {
            push @{ $response{$qtype} }, $rr;
            next;
        }
    }

    if ( $#{ $response{$qtype} } < 0 ) {    # FIXME: This must be a bug
        return;
    }

    return \%response;
}

sub _check_signature {
    my $parent = shift;
    my $zone   = shift;
    my $rrsig  = shift;
    my $keys   = shift;
    my $rrset  = shift;

    my $result;

    my $logger = $parent->logger;

    die "bad call to check_signature()" unless ( $rrsig->type eq "RRSIG" );

    my $now = time();

    my $inception  = _parse_timestamp( $rrsig->siginception );
    my $expiration = _parse_timestamp( $rrsig->sigexpiration );
    my $duration = $expiration - $inception;

    my $message = sprintf( "RRSIG(%s/%s/%s/%d)", $rrsig->name, $rrsig->class, $rrsig->typecovered, $rrsig->keytag );

    if ( $inception > $now ) {
        $logger->auto( "DNSSEC:RRSIG_NOT_YET_VALID", $message );
        return 0;
    }
    elsif ( $expiration < $now ) {
        $logger->auto( "DNSSEC:RRSIG_EXPIRED", $message );
        return 0;
    }
    else {
        $logger->auto( "DNSSEC:RRSIG_EXPIRES_AT", scalar( gmtime( $expiration ) ) );
    }

    if ($duration < 43200) { # 12 hours
        $logger->auto('DNSSEC:RRSIG_SHORT_DURATION', $message, $duration);
    } elsif ($duration > 15552000) { # 180 days
        $logger->auto('DNSSEC:RRSIG_LONG_DURATION', $message, $duration);
    } else {
        $logger->auto('DNSSEC:RRSIG_OK_DURATION', $message, $duration);
    }

    if ( $keys and $rrsig->verify( $rrset, $keys ) ) {
        $logger->auto( "DNSSEC:RRSIG_VERIFIES", $message );
    }
    else {
        $logger->auto( "DNSSEC:RRSIG_FAILS_VERIFY", $message, $rrsig->vrfyerrstr );
        return 0;
    }

    $logger->auto( "DNSSEC:RRSIG_VALID", $message );
    return 1;
}

sub _parse_timestamp {
    my $str = shift;

    if ( $str =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/ ) {
        return str2time( "$1-$2-$3 $4:$5:$6", "GMT" );
    }
    else {
        return;
    }
}

sub _count_in_list {
    my $value = shift;
    my $list  = shift;

    my $n = 0;

    foreach my $x ( @{$list} ) {
        $n++ if ( $x == $value );
    }

    return $n;
}

sub check_algorithm {
    my $logger = shift;
    my $aid    = shift;

    #    0   => Reserved
    #    1   => RSA/MD5 (deprecated)
    #    2   => Diffie-Hellman
    #    3   => DSA/SHA1
    #    4   => Reserved (ECC)
    #    5   => RSA/SHA-1
    #    6   => DSA-NSEC3-SHA1
    #    7   => RSA-NSEC3-SHA1
    #    8   => RSA/SHA-256
    #    9   => Unassigned
    #    10  => RSA/SHA-512
    #    11  => Unassigned
    #    12  => GOST R 34.10-2001
    #    13  => ECDSA Curve P-256 with SHA-256
    #    14  => ECDSA Curve P-384 with SHA-384
    #    15  => Ed25519
    #    16  => Ed448
    #    17-122 => Unassigned
    #    123-251 => Reserved
    #    252 => Reserved (Indirect keys)
    #    253 => Private algorithm (domain name)
    #    254 => Private algorithm (OID)
    #    255 => Reserved

    if ( $aid == 1 ) {
        return $logger->auto( 'DNSSEC:ALGORITHM_DEPRECATED', $aid );
    }
    elsif ( $aid == 0 or $aid == 4 or ( $aid >= 123 and $aid <= 252 ) or $aid == 255 ) {
        return $logger->auto( 'DNSSEC:ALGORITHM_RESERVED', $aid );
    }
    elsif ( $aid == 9 or $aid == 11 or ( $aid >= 17 and $aid <= 122 ) ) {
        return $logger->auto( 'DNSSEC:ALGORITHM_UNASSIGNED', $aid );
    }
    elsif ( $aid == 253 or $aid == 254 ) {
        return $logger->auto( 'DNSSEC:ALGORITHM_PRIVATE', $aid );
    }
    else {
        return $logger->auto( 'DNSSEC:ALGORITHM_OK', $aid );
    }
}

1;

__END__


=head1 NAME

DNSCheck::Test::DNSSEC - Test DNSSEC

=head1 DESCRIPTION

=over 4

=item *
If there exists DS at parent, the child must use DNSSEC.

=item *
If there exists DNSKEY at child, the parent should have a DS.

=item *
A DNSSEC key should not be of type RSA/MD5.

=item *
At least one DNSKEY should be of type RSA/SHA1.

=item *
There may exist a SEP at the child.

=item *
RRSIG(DNSKEY) must be valid and created by a valid DNSKEY.

=item *
RRSIG(SOA) must be valid and created by a valid DNSKEY.

=item *
The DS must point to a DNSKEY signing the child's DNSKEY RRset.

=item *
The DS may point to a SEP at the child.

=item *
At least one DS algorithm should be of type RSA/SHA1.

=back

=head1 METHODS

=over

=item ->test($zonename)

=item ->rrsig_validities($zonename)

=item ->algorithm_name($id)

Return the name appropriate for the given algorithm ID number.

=item ->check_algorithm($id)

Check if the given algorithm ID number specifies an algorithm valid for use, of 
if not what kind of wrong it is.

=back

=head1 EXAMPLES

=head1 SEE ALSO

L<DNSCheck>, L<DNSCheck::Logger>

=cut
