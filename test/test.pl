#!/usr/bin/perl
#

use IO::Socket;

our $DEBUG = 1;
our $HOST;

sub dbg { print STDERR $_[0], "\n" if $DEBUG }

sub client_init() {

    my $sock = IO::Socket::INET->new(PeerAddr => $HOST, 
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

sub test_fragmentation
{
# Send a fragmented line
    $sock = client_init();
    $sock->print("qu");
    $sock->flush();
    dbg("sent 2, sleeping..");
    sleep 3;
    $sock->print("it");
    $sock->flush();
    dbg("sent 2, sleeping..");
    sleep 3;
    $sock->print("\r\n");
    $sock->flush();
    expect($sock, "221");
    $sock->close();
}

sub test_overflow()
{
#Send a large amount of data to try and overflow the buffer
    $sock = client_init();
    for (my $x = 0; $x < 500000; $x++) {
        $sock->print(".");
    }
    $sock->close();
}

#################################################################
#

my $sock;

$HOST = shift @ARGV or die "usage: test <hostname>";

test_fragmentation();
#test_overflow()
