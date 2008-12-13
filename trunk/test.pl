#!/usr/bin/perl
#

use IO::Socket;

sub client_init() {
    my $sock = IO::Socket::INET->new(PeerAddr => 'localhost', 
            PeerPort => '1025',
            Proto    => 'tcp');
    die "$!" unless $sock;

    $sock->autoflush();

    return $sock;
}

sub expect($$) {
    my $sock = shift;
    my $line = $sock->getline();
    warn $line;
}

#################################################################
#

my $sock;

# Check for the 220 greeting
$sock = client_init();
expect($sock, "220");

# Send a fragmented line
$sock->print("qu");
$sock->flush();
sleep 1;
$sock->print("it");
$sock->flush();
sleep 1;
$sock->print("\r\n");
$sock->flush();
expect($sock, "221");
