"""Header records for feeding the detector directly, without building frames."""

from ids.packets import ACK, ARP_KIND, RST, SYN, TCP_KIND, PacketInfo

GATEWAY_MAC, ATTACKER_MAC, NEW_MAC = "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:66", "aa:aa:aa:aa:aa:99"


def tcp(ts, src, dst, sport, dport, flags, src_mac=None):
    return PacketInfo(ts, TCP_KIND, src_mac=src_mac, src_ip=src, dst_ip=dst,
                      sport=sport, dport=dport, flags=flags)


def arp(ts, ip, mac):
    return PacketInfo(ts, ARP_KIND, src_mac=mac, src_ip=ip, dst_ip=ip, arp_op=2, arp_mac=mac)


def refused(detector, ts, src, dst, sport, dport):
    detector.handle_info(tcp(ts, src, dst, sport, dport, SYN))
    detector.handle_info(tcp(ts + 0.001, dst, src, dport, sport, RST | ACK))


def handshake(detector, ts, src, dst, sport, dport):
    detector.handle_info(tcp(ts, src, dst, sport, dport, SYN))
    detector.handle_info(tcp(ts + 0.001, dst, src, dport, sport, SYN | ACK))
    detector.handle_info(tcp(ts + 0.002, src, dst, sport, dport, ACK))
