"""Builds Ethernet frames with timestamps. Checksums and lengths are left unset
so Scapy computes them when the file is written."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from .hosts import Host, Network

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
# What an ordinary client stack offers; scanners and flood tools send less.
SYN_OPTIONS = [("MSS", 1460), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", b"")]
MSS_ONLY = [("MSS", 1460)]
SEGMENT = 1400
M32 = 0xFFFFFFFF


class Frames:
    # Scapy constructs the Ethernet/IP/TCP/UDP/ARP layers here.
    # Our code chooses who talks, when, and with which flags and payload lengths.
    # The detection rules are elsewhere: ids/rules.py never consults this builder.
    def __init__(self, network: Network, random_generator):
        self.network = network
        self.random_generator = random_generator
        self.out: list = []

    def _add(self, timestamp: float, captured_packet) -> None:
        captured_packet.time = timestamp
        self.out.append(captured_packet)

    def _ip(self, timestamp: float, source_ip: str, destination_ip: str):
        network = self.network
        return Ether(src=network.mac_for(source_ip, timestamp), dst=network.mac_for(destination_ip, timestamp)) / \
            IP(src=source_ip, dst=destination_ip, ttl=network.ttl_for(source_ip),
                id=network.next_ip_id(source_ip), flags="DF")

    def tcp(self, timestamp, source_ip, destination_ip, source_port, destination_port, flags, sequence_number=0,
            acknowledgment_number=0, payload=b"", options=None):
        captured_packet = self._ip(timestamp, source_ip, destination_ip) / TCP(sport=source_port,
            dport=destination_port, flags=flags, seq=sequence_number & M32,
            ack=acknowledgment_number & M32, window=64240, options=options or [])
        if payload:
            captured_packet = captured_packet / Raw(load=payload)
        self._add(timestamp, captured_packet)

    def round_trip_time(self, first_host: str, second_host: str) -> float:
        if self.network.is_local(first_host) and self.network.is_local(second_host):
            return self.random_generator.uniform(0.0003, 0.002)
        return self.random_generator.uniform(0.012, 0.06)

    def session(self, timestamp, client, server, destination_port, request: bytes, segments: list[bytes],
                client_port=None, initial_sequence=None) -> float:
        """A complete connection: handshake, request, response, close. Returns the end time."""
        # S -> SA -> A is the normal three-way handshake.
        # Each SYN consumes one sequence number, so the peer acknowledges +1.
        # Payload bytes advance sequence numbers; later FA packets close the flow.
        # tests/test_mock.py checks handshake numbers; the detector itself only
        # recognizes the flag sequence and connection tuple, not those numbers.
        random_generator = self.random_generator
        client_port = client_port or self.network.next_port(client)
        round_trip_time = self.round_trip_time(client, server)
        client_sequence = random_generator.getrandbits(32) if initial_sequence is None else initial_sequence
        server_sequence = random_generator.getrandbits(32)

        self.tcp(timestamp, client, server, client_port, destination_port, "S", sequence_number=client_sequence,
            options=SYN_OPTIONS)
        timestamp += round_trip_time
        self.tcp(timestamp, server, client, destination_port, client_port, "SA",
            sequence_number=server_sequence, acknowledgment_number=client_sequence + 1, options=SYN_OPTIONS)
        timestamp += random_generator.uniform(0.0001, 0.0005)
        self.tcp(timestamp, client, server, client_port, destination_port, "A",
            sequence_number=client_sequence + 1, acknowledgment_number=server_sequence + 1)
        timestamp += random_generator.uniform(0.0005, 0.01)
        self.tcp(timestamp, client, server, client_port, destination_port, "PA",
            sequence_number=client_sequence + 1, acknowledgment_number=server_sequence + 1, payload=request)
        client_next_sequence, server_next_sequence = client_sequence + 1 + len(request), server_sequence + 1
        timestamp += round_trip_time
        self.tcp(timestamp, server, client, destination_port, client_port, "A",
            sequence_number=server_next_sequence, acknowledgment_number=client_next_sequence)
        for segment in segments:
            timestamp += random_generator.uniform(0.0002, 0.003)
            self.tcp(timestamp, server, client, destination_port, client_port, "PA",
                sequence_number=server_next_sequence, acknowledgment_number=client_next_sequence, payload=segment)
            server_next_sequence += len(segment)
            timestamp += random_generator.uniform(0.0001, 0.0005)
            self.tcp(timestamp, client, server, client_port, destination_port, "A",
                sequence_number=client_next_sequence, acknowledgment_number=server_next_sequence)
        timestamp += random_generator.uniform(0.001, 0.05)
        self.tcp(timestamp, client, server, client_port, destination_port, "FA",
            sequence_number=client_next_sequence, acknowledgment_number=server_next_sequence)
        timestamp += round_trip_time
        self.tcp(timestamp, server, client, destination_port, client_port, "FA",
            sequence_number=server_next_sequence, acknowledgment_number=client_next_sequence + 1)
        timestamp += random_generator.uniform(0.0001, 0.0005)
        self.tcp(timestamp, client, server, client_port, destination_port, "A",
            sequence_number=client_next_sequence + 1, acknowledgment_number=server_next_sequence + 1)
        return timestamp

    def refused(self, timestamp, client, server, destination_port, client_port=None) -> None:
        """SYN to a closed port, answered with RST."""
        client_port = client_port or self.network.next_port(client)
        client_sequence = self.random_generator.getrandbits(32)
        self.tcp(timestamp, client, server, client_port, destination_port, "S", sequence_number=client_sequence,
            options=SYN_OPTIONS)
        self.tcp(timestamp + self.round_trip_time(client, server), server, client, destination_port,
            client_port, "RA", acknowledgment_number=client_sequence + 1)

    def unanswered(self, timestamp, client, server, destination_port, retries=2, client_port=None,
        initial_sequence=None) -> None:
        """SYN that gets no reply, retransmitted with the usual 1 s, 2 s backoff."""
        client_port = client_port or self.network.next_port(client)
        client_sequence = self.random_generator.getrandbits(32) if initial_sequence is None else initial_sequence
        delay = 0.0
        for attempt in range(retries + 1):
            self.tcp(timestamp + delay, client, server, client_port, destination_port, "S",
                sequence_number=client_sequence, options=SYN_OPTIONS)
            delay += 2 ** attempt

    def dns(self, timestamp, client, server, name: str, answer: str) -> float:
        source_port = self.network.next_port(client)
        query_id = self.random_generator.getrandbits(16)
        question = DNSQR(qname=name)
        self._add(timestamp, self._ip(timestamp, client, server) / UDP(sport=source_port, dport=53) /
                  DNS(id=query_id, rd=1, qd=question))
        timestamp += self.round_trip_time(client, server) + self.random_generator.uniform(0.001, 0.03)
        self._add(timestamp, self._ip(timestamp, server, client) / UDP(sport=53, dport=source_port) /
                  DNS(id=query_id, qr=1, rd=1, ra=1, qd=question,
                      an=DNSRR(rrname=name, ttl=300, rdata=answer)))
        return timestamp

    def arp_request(self, timestamp, mac: str, ip: str, wanted_ip: str) -> None:
        self._add(timestamp, Ether(src=mac, dst=BROADCAST) /
                  ARP(op=1, hwsrc=mac, psrc=ip, hwdst=ZERO_MAC, pdst=wanted_ip))

    def arp_reply(self, timestamp, mac: str, ip: str, to_mac: str, to_ip: str) -> None:
        self._add(timestamp, Ether(src=mac, dst=to_mac) /
                  ARP(op=2, hwsrc=mac, psrc=ip, hwdst=to_mac, pdst=to_ip))

    def arp_exchange(self, timestamp, asker: Host, owner: Host) -> None:
        self.arp_request(timestamp, asker.mac_at(timestamp), asker.ip, owner.ip)
        timestamp += self.random_generator.uniform(0.0002, 0.002)
        self.arp_reply(timestamp, owner.mac_at(timestamp), owner.ip, asker.mac_at(timestamp), asker.ip)


def http_request(host: str, path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mock/1.0\r\nAccept: */*\r\n\r\n".encode()


def http_response(random_generator, size: int) -> list[bytes]:
    body = bytes(random_generator.choice(b"abcdefghijklmnopqrstuvwxyz \n") for _ in range(size))
    data = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {size}\r\n\r\n"
            .encode() + body)
    return [data[index:index + SEGMENT] for index in range(0, len(data), SEGMENT)]


def tls_record(random_generator, size: int) -> bytes:
    """An opaque TLS 1.2 application data record."""
    # Mock payload bytes, not an actual encrypted TLS session. These make traffic
    # sizes varied; header-based detection does not inspect their contents.
    return b"\x17\x03\x03" + size.to_bytes(2, "big") + random_generator.randbytes(size)


def tls_records(random_generator, count: int) -> list[bytes]:
    return [tls_record(random_generator, random_generator.randrange(300, SEGMENT - 5)) for _ in range(count)]
