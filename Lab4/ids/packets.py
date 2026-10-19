"""Reduce a captured frame to the header fields the rules need."""

from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

TCP_KIND, UDP_KIND, ARP_KIND, OTHER_KIND = "tcp", "udp", "arp", "other"

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class PacketInfo:
    # Header fields shared by state tracking, detection and playback.
    # Scapy decodes packet formats; our state and rules interpret the behavior.
    timestamp: float
    kind: str
    source_mac: str | None = None
    destination_mac: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int = 0
    destination_port: int = 0
    flags: int = 0
    arp_operation: int = 0
    arp_sender_mac: str | None = None  # sender hardware address inside the ARP payload


def decode(captured_packet) -> PacketInfo:
    """Headers only: payloads are never read, so encrypted traffic decodes the same."""
    # The three rules need addresses, ports, flags and timing,
    # not application content. Ordinary TLS does not hide those outer headers;
    # a tunnel or an incomplete capture can still hide the traffic we need.
    packet_info = PacketInfo(timestamp=float(captured_packet.time), kind=OTHER_KIND)
    ethernet_layer = captured_packet.getlayer(Ether)
    if ethernet_layer is not None:
        packet_info.source_mac = ethernet_layer.src
        packet_info.destination_mac = ethernet_layer.dst

    arp = captured_packet.getlayer(ARP)
    if arp is not None:
        # ARP says "this IP belongs to this MAC": psrc is the claimed sender IP
        # and hwsrc the claimed hardware address. The Ethernet source is stored
        # separately because an address claim is not proof of the sender's identity.
        packet_info.kind = ARP_KIND
        packet_info.arp_operation = arp.op
        packet_info.arp_sender_mac = arp.hwsrc
        packet_info.source_ip = arp.psrc
        packet_info.destination_ip = arp.pdst
        return packet_info

    # This lookup handles IPv4, not IPv6. Other Ethernet traffic
    # can still contribute MAC activity, but has no TCP/ARP detection rule here.
    ip = captured_packet.getlayer(IP)
    if ip is None:
        return packet_info
    packet_info.source_ip = ip.src
    packet_info.destination_ip = ip.dst

    transport_layer = ip.payload
    if isinstance(transport_layer, TCP):
        packet_info.kind = TCP_KIND
        packet_info.source_port = transport_layer.sport
        packet_info.destination_port = transport_layer.dport
        packet_info.flags = int(transport_layer.flags)
    elif isinstance(transport_layer, UDP):
        # UDP fields support statistics and playback; there is no UDP scan rule.
        packet_info.kind = UDP_KIND
        packet_info.source_port = transport_layer.sport
        packet_info.destination_port = transport_layer.dport
    return packet_info
