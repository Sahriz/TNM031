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
    def __init__(self, net: Network, rng):
        self.net = net
        self.rng = rng
        self.out: list = []

    def _add(self, t: float, pkt) -> None:
        pkt.time = t
        self.out.append(pkt)

    def _ip(self, t: float, src: str, dst: str):
        net = self.net
        return Ether(src=net.mac_for(src, t), dst=net.mac_for(dst, t)) / \
            IP(src=src, dst=dst, ttl=net.ttl_for(src), id=net.next_ip_id(src), flags="DF")

    def tcp(self, t, src, dst, sport, dport, flags, seq=0, ack=0, payload=b"", options=None):
        pkt = self._ip(t, src, dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq & M32,
                                          ack=ack & M32, window=64240, options=options or [])
        if payload:
            pkt = pkt / Raw(load=payload)
        self._add(t, pkt)

    def rtt(self, a: str, b: str) -> float:
        if self.net.is_local(a) and self.net.is_local(b):
            return self.rng.uniform(0.0003, 0.002)
        return self.rng.uniform(0.012, 0.06)

    def session(self, t, client, server, dport, request: bytes, segments: list[bytes],
                cport=None, isn=None) -> float:
        """A complete connection: handshake, request, response, close. Returns the end time."""
        rng = self.rng
        cport = cport or self.net.next_port(client)
        rtt = self.rtt(client, server)
        c = rng.getrandbits(32) if isn is None else isn
        s = rng.getrandbits(32)

        self.tcp(t, client, server, cport, dport, "S", seq=c, options=SYN_OPTIONS)
        t += rtt
        self.tcp(t, server, client, dport, cport, "SA", seq=s, ack=c + 1, options=SYN_OPTIONS)
        t += rng.uniform(0.0001, 0.0005)
        self.tcp(t, client, server, cport, dport, "A", seq=c + 1, ack=s + 1)
        t += rng.uniform(0.0005, 0.01)
        self.tcp(t, client, server, cport, dport, "PA", seq=c + 1, ack=s + 1, payload=request)
        cseq, sseq = c + 1 + len(request), s + 1
        t += rtt
        self.tcp(t, server, client, dport, cport, "A", seq=sseq, ack=cseq)
        for segment in segments:
            t += rng.uniform(0.0002, 0.003)
            self.tcp(t, server, client, dport, cport, "PA", seq=sseq, ack=cseq, payload=segment)
            sseq += len(segment)
            t += rng.uniform(0.0001, 0.0005)
            self.tcp(t, client, server, cport, dport, "A", seq=cseq, ack=sseq)
        t += rng.uniform(0.001, 0.05)
        self.tcp(t, client, server, cport, dport, "FA", seq=cseq, ack=sseq)
        t += rtt
        self.tcp(t, server, client, dport, cport, "FA", seq=sseq, ack=cseq + 1)
        t += rng.uniform(0.0001, 0.0005)
        self.tcp(t, client, server, cport, dport, "A", seq=cseq + 1, ack=sseq + 1)
        return t

    def refused(self, t, client, server, dport, cport=None) -> None:
        """SYN to a closed port, answered with RST."""
        cport = cport or self.net.next_port(client)
        c = self.rng.getrandbits(32)
        self.tcp(t, client, server, cport, dport, "S", seq=c, options=SYN_OPTIONS)
        self.tcp(t + self.rtt(client, server), server, client, dport, cport, "RA", ack=c + 1)

    def unanswered(self, t, client, server, dport, retries=2, cport=None, isn=None) -> None:
        """SYN that gets no reply, retransmitted with the usual 1 s, 2 s backoff."""
        cport = cport or self.net.next_port(client)
        c = self.rng.getrandbits(32) if isn is None else isn
        delay = 0.0
        for attempt in range(retries + 1):
            self.tcp(t + delay, client, server, cport, dport, "S", seq=c, options=SYN_OPTIONS)
            delay += 2 ** attempt

    def dns(self, t, client, server, name: str, answer: str) -> float:
        sport = self.net.next_port(client)
        qid = self.rng.getrandbits(16)
        question = DNSQR(qname=name)
        self._add(t, self._ip(t, client, server) / UDP(sport=sport, dport=53) /
                  DNS(id=qid, rd=1, qd=question))
        t += self.rtt(client, server) + self.rng.uniform(0.001, 0.03)
        self._add(t, self._ip(t, server, client) / UDP(sport=53, dport=sport) /
                  DNS(id=qid, qr=1, rd=1, ra=1, qd=question,
                      an=DNSRR(rrname=name, ttl=300, rdata=answer)))
        return t

    def arp_request(self, t, mac: str, ip: str, wanted_ip: str) -> None:
        self._add(t, Ether(src=mac, dst=BROADCAST) /
                  ARP(op=1, hwsrc=mac, psrc=ip, hwdst=ZERO_MAC, pdst=wanted_ip))

    def arp_reply(self, t, mac: str, ip: str, to_mac: str, to_ip: str) -> None:
        self._add(t, Ether(src=mac, dst=to_mac) /
                  ARP(op=2, hwsrc=mac, psrc=ip, hwdst=to_mac, pdst=to_ip))

    def arp_exchange(self, t, asker: Host, owner: Host) -> None:
        self.arp_request(t, asker.mac_at(t), asker.ip, owner.ip)
        t += self.rng.uniform(0.0002, 0.002)
        self.arp_reply(t, owner.mac_at(t), owner.ip, asker.mac_at(t), asker.ip)


def http_request(host: str, path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mock/1.0\r\nAccept: */*\r\n\r\n".encode()


def http_response(rng, size: int) -> list[bytes]:
    body = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz \n") for _ in range(size))
    data = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {size}\r\n\r\n"
            .encode() + body)
    return [data[i:i + SEGMENT] for i in range(0, len(data), SEGMENT)]


def tls_record(rng, size: int) -> bytes:
    """An opaque TLS 1.2 application data record."""
    return b"\x17\x03\x03" + size.to_bytes(2, "big") + rng.randbytes(size)


def tls_records(rng, count: int) -> list[bytes]:
    return [tls_record(rng, rng.randrange(300, SEGMENT - 5)) for _ in range(count)]
