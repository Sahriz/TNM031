"""Header records for feeding the detector directly, without building frames."""

from ids.packets import ACK, ARP_KIND, RST, SYN, TCP_KIND, PacketInfo

GATEWAY_MAC, ATTACKER_MAC, NEW_MAC = "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:66", "aa:aa:aa:aa:aa:99"


def tcp(timestamp, source_ip, destination_ip, source_port, destination_port, flags, source_mac=None):
    return PacketInfo(timestamp, TCP_KIND, source_mac=source_mac, source_ip=source_ip, destination_ip=destination_ip,
                      source_port=source_port, destination_port=destination_port, flags=flags)


def arp(timestamp, ip, mac):
    return PacketInfo(timestamp, ARP_KIND, source_mac=mac, source_ip=ip, destination_ip=ip, arp_operation=2, arp_sender_mac=mac)


def refused(detector, timestamp, source_ip, destination_ip, source_port, destination_port):
    detector.handle_info(tcp(timestamp, source_ip, destination_ip, source_port, destination_port, SYN))
    detector.handle_info(tcp(timestamp + 0.001, destination_ip, source_ip, destination_port, source_port, RST | ACK))


def handshake(detector, timestamp, source_ip, destination_ip, source_port, destination_port):
    detector.handle_info(tcp(timestamp, source_ip, destination_ip, source_port, destination_port, SYN))
    detector.handle_info(tcp(timestamp + 0.001, destination_ip, source_ip, destination_port, source_port, SYN | ACK))
    detector.handle_info(tcp(timestamp + 0.002, source_ip, destination_ip, source_port, destination_port, ACK))
