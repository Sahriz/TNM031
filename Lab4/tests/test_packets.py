from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from ids.packets import ACK, ARP_KIND, OTHER_KIND, SYN, TCP_KIND, UDP_KIND, decode


def reparse(captured_packet, timestamp=12.5):
    """Round-trip through bytes, as PcapReader would deliver it."""
    parsed = Ether(bytes(captured_packet))
    parsed.time = timestamp
    return parsed


def test_tcp_headers():
    packet_info = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="aa:00:00:00:00:02") /
                       IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=443, flags="SA")))
    assert (packet_info.kind, packet_info.timestamp) == (TCP_KIND, 12.5)
    assert (packet_info.source_ip, packet_info.destination_ip, packet_info.source_port, packet_info.destination_port) == ("10.0.0.5", "10.0.0.9", 50000, 443)
    assert packet_info.flags == SYN | ACK
    assert (packet_info.source_mac, packet_info.destination_mac) == ("aa:00:00:00:00:01", "aa:00:00:00:00:02")


def test_udp_headers():
    packet_info = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="aa:00:00:00:00:02") /
                       IP(src="10.0.0.5", dst="10.0.0.11") / UDP(sport=50001, dport=53) /
                       DNS(qd=DNSQR(qname="www.shop.example"))))
    assert (packet_info.kind, packet_info.source_port, packet_info.destination_port) == (UDP_KIND, 50001, 53)


def test_arp_sender():
    packet_info = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op=2, hwsrc="aa:00:00:00:00:01", psrc="10.0.0.1", pdst="10.0.0.7")))
    assert (packet_info.kind, packet_info.arp_operation) == (ARP_KIND, 2)
    assert (packet_info.source_ip, packet_info.arp_sender_mac, packet_info.destination_ip) == ("10.0.0.1", "aa:00:00:00:00:01", "10.0.0.7")


def test_other_traffic_keeps_mac():
    packet_info = decode(reparse(Ether(src="aa:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff", type=0x88CC) / (b"\x00" * 46)))
    assert (packet_info.kind, packet_info.source_mac, packet_info.source_ip) == (OTHER_KIND, "aa:00:00:00:00:01", None)
