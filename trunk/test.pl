#!/usr/bin/perl
#

use IO::Socket;

sub client_init() {
    my $sock = IO::Socket::INET->new(PeerAddr => 'localhost', 
            PeerPort => '1025',
            Proto    => 'tcp');
    die "$!" unless $sock;

    $sock->autoflush();

    expect($sock, "220");
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

#Send a large amount of data to try and overflow the buffer
$sock = client_init();
for (my $x = 0; $x < 500000; $x++) {
    $sock->print(".");
}
$sock->close();

# Send a fragmented line
$sock = client_init();
$sock->print("qu");
$sock->flush();
sleep 1;
$sock->print("it");
$sock->flush();
sleep 1;
$sock->print("\r\n");
$sock->flush();
expect($sock, "221");
