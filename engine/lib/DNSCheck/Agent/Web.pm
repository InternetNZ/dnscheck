#!/usr/bin/perl
#
# XXX
# Description and author
##################################################################

package DNSCheck::Agent::Web;

require 5.010001;
use warnings;
use strict;
use utf8;

use LWP::UserAgent;
use HTTP::Headers;

# Map protocol to port to build a proper Host HTTP Header
our %service2port = (
    'http'  => 80,
    'https' => 443,
);

sub new {
    my $proto = shift;
    my $class = ref( $proto ) || $proto;
    my $self  = {};
    bless $self, $class;

    $self->{parent} = shift;

    # Get some values from the configuration file
    # XXX What if the web section is not defined?
    $self->{agent}   = $self->{parent}->config->get( "web" )->{agent};
    $self->{from}    = $self->{parent}->config->get( "web" )->{from};
    $self->{timeout} = $self->{parent}->config->get( "web" )->{timeout};

    # Setup HTTP Headers and agent
    $self->{user_agent} = LWP::UserAgent->new( {
                            agent => $self->{agent} // 'libwww-perl',
                            from  => $self->{from} // 'support@nzrs.net.nz',
                            timeout => $self->{timeout} // 5 });

    return $self;
}

sub parent {
    my $self = shift;

    return $self->{parent};
}

sub request {
    my $self = shift;
    my $proto = shift // 'http';
    my $webserver = shift;
    my $address = shift;

    my $url = $proto . "://" . $address . $self->{resource};
    my $response = $self->{user_agent}->get( $url,
                { 'Host' => $webserver .  ':' .  $service2port{$proto} } // 0);

    return XXX;
}

1;

__END__


=head1 NAME

DNSCheck::Agent::Web - Web agent 

=head1 DESCRIPTION

Helper function for sending web requests to web servers

=head1 METHODS

=head2 request($protocol, $webserver, $ip)

Sends a web request of protocol $protocol to the address pointed by $ip,
identifying the request as related to $webserver (useful in case of
shared ip webhosting). Current protocols supported: HTTP, HTTPS
Returns an empty array in case of failure, or two-value array with
response code and content length if it worked.

=head2 flush()

Discard all cached lookups.

=head2 new($parent)

This is not meant to be called directly. Get an object by calling the 
L<DNSCheck::asn()> method instead;

=head2 parent()

Returns a reference to the current parent object.

=head1 EXAMPLES

    use DNSCheck;

    my $asn    = DNSCheck->new->asn;

    $asn->lookup("64.233.183.99");

=head1 SEE ALSO

L<DNSCheck>

=cut
