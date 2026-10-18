"""Reduce a captured frame to the header fields the rules need."""

from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

TCP_KIND, UDP_KIND, ARP_KIND, OTHER_KIND = "tcp", "udp", "arp", "other"

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass(slots=True)
class PacketInfo:
    ts: float
    kind: str
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    sport: int = 0
    dport: int = 0
    flags: int = 0
    arp_op: int = 0
    arp_mac: str | None = None  # sender hardware address inside the ARP payload


def decode(pkt) -> PacketInfo:
    """Headers only: payloads are never read, so encrypted traffic decodes the same."""
    info = PacketInfo(ts=float(pkt.time), kind=OTHER_KIND)
    ether = pkt.getlayer(Ether)
    if ether is not None:
        info.src_mac = ether.src
        info.dst_mac = ether.dst

    arp = pkt.getlayer(ARP)
    if arp is not None:
        info.kind = ARP_KIND
        info.arp_op = arp.op
        info.arp_mac = arp.hwsrc
        info.src_ip = arp.psrc
        info.dst_ip = arp.pdst
        return info

    ip = pkt.getlayer(IP)
    if ip is None:
        return info
    info.src_ip = ip.src
    info.dst_ip = ip.dst

    l4 = ip.payload
    if isinstance(l4, TCP):
        info.kind = TCP_KIND
        info.sport = l4.sport
        info.dport = l4.dport
        info.flags = int(l4.flags)
    elif isinstance(l4, UDP):
        info.kind = UDP_KIND
        info.sport = l4.sport
        info.dport = l4.dport
    return info
