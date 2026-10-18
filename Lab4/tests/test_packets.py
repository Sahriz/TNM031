from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from ids.packets import ACK, ARP_KIND, OTHER_KIND, SYN, TCP_KIND, UDP_KIND, decode


def reparse(pkt, ts=12.5):
    """Round-trip through bytes, as PcapReader would deliver it."""
    parsed = Ether(bytes(pkt))
    parsed.time = ts
    return parsed


def test_tcp_headers():
    p = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="aa:00:00:00:00:02") /
                       IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=443, flags="SA")))
    assert (p.kind, p.ts) == (TCP_KIND, 12.5)
    assert (p.src_ip, p.dst_ip, p.sport, p.dport) == ("10.0.0.5", "10.0.0.9", 50000, 443)
    assert p.flags == SYN | ACK
    assert (p.src_mac, p.dst_mac) == ("aa:00:00:00:00:01", "aa:00:00:00:00:02")


def test_udp_headers():
    p = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="aa:00:00:00:00:02") /
                       IP(src="10.0.0.5", dst="10.0.0.11") / UDP(sport=50001, dport=53) /
                       DNS(qd=DNSQR(qname="www.shop.example"))))
    assert (p.kind, p.sport, p.dport) == (UDP_KIND, 50001, 53)


def test_arp_sender():
    p = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op=2, hwsrc="aa:00:00:00:00:01", psrc="10.0.0.1", pdst="10.0.0.7")))
    assert (p.kind, p.arp_op) == (ARP_KIND, 2)
    assert (p.src_ip, p.arp_mac, p.dst_ip) == ("10.0.0.1", "aa:00:00:00:00:01", "10.0.0.7")


def test_other_traffic_keeps_mac():
    p = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff", type=0x88CC) / (b"\x00" * 46)))
    assert (p.kind, p.src_mac, p.src_ip) == (OTHER_KIND, "aa:00:00:00:00:01", None)
