#!/usr/bin/perl
# Benign Modbus traffic from the approved HMI (172.22.0.10).
#
# Reads the normal HR0..6 block, writes the unused pump-speed register
# (HR1 = 50) as an approved writer, and every tenth cycle reads the unmapped
# HR100 to produce a benign exception response. No process or safety register
# is changed.
use strict;
use warnings;
use IO::Socket::INET;

my $plc = "172.21.0.10";
my $port = 502;
my $cycle = 0;

sub exchange {
    my ($sock, $pdu, $tid) = @_;
    my $mbap = pack("n n n C", $tid, 0, length($pdu) + 1, 1);
    print $sock $mbap . $pdu;
    my $header;
    return undef unless read($sock, $header, 7) == 7;
    my ($rtid, $proto, $len, $unit) = unpack("n n n C", $header);
    my $body;
    read($sock, $body, $len - 1);
    return $body;
}

while (1) {
    $cycle++;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $plc, PeerPort => $port, Proto => "tcp", Timeout => 3
    ) or do { print "[modbus] connect failed: $!\n"; sleep 10; next; };

    my $tid = $cycle & 0xffff;
    my $read = exchange($sock, pack("C n n", 3, 0, 7), $tid);
    print "[modbus] read HR0..6 ", (defined $read ? unpack("H*", $read) : "no response"), "\n";

    my $write = exchange($sock, pack("C n n", 6, 1, 50), ($tid + 1) & 0xffff);
    print "[modbus] write HR1=50 ", (defined $write ? unpack("H*", $write) : "no response"), "\n";

    if ($cycle % 10 == 0) {
        my $probe = exchange($sock, pack("C n n", 3, 100, 1), ($tid + 2) & 0xffff);
        print "[modbus] probe HR100 ", (defined $probe ? unpack("H*", $probe) : "no response"), "\n";
    }

    close $sock;
    sleep 10;
}
