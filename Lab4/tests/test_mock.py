import json

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapReader

from ids.detector import Detector
from mock import generate

# Checks cover ordering, labels, sampled checksums, handshake numbers and
# reproducibility. Valid packet structure does not establish that generated
# traffic has the same distribution as traffic recorded on a real network.


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    frames, labels = generate.build(seed=7, index=0, duration=180.0)
    stem = tmp_path_factory.mktemp("mock") / "sample"
    generate.write(stem, frames, labels)
    with PcapReader(str(stem.with_suffix(".pcap"))) as reader:
        packets = list(reader)
    return packets, json.loads(stem.with_suffix(".labels.json").read_text())


def test_file_is_time_ordered_and_inside_the_capture(capture):
    packets, labels = capture
    times = [float(packet_info.time) for packet_info in packets]
    assert times == sorted(times)
    assert labels["start"] <= times[0] and times[-1] < labels["start"] + labels["duration"]


def test_labels_cover_every_attack_and_lookalike(capture):
    _, labels = capture
    events = labels["events"]
    assert sorted(e["rule"] for e in events if e["kind"] == "attack") == ["arp_spoof", "port_scan", "syn_flood"]
    assert sorted(e["subtype"] for e in events if e["kind"] == "benign") == [
        "backup_job", "flash_crowd", "nic_replacement", "peer_discovery"]
    assert len({e["id"] for e in events}) == len(events)
    for e in events:
        assert labels["start"] <= e["start"] <= e["end"]


def test_checksums_are_valid(capture):
    # We sample every 25th frame, select TCP packets, recompute IP/TCP checksums
    # through Scapy and compare. This does not inspect every packet in the dataset.
    packets, _ = capture
    checked = 0
    for captured_packet in packets[::25]:
        if TCP not in captured_packet:
            continue
        ip_sum, tcp_sum = captured_packet[IP].chksum, captured_packet[TCP].chksum
        del captured_packet[IP].chksum, captured_packet[TCP].chksum
        rebuilt = IP(bytes(captured_packet[IP]))
        assert (rebuilt.chksum, rebuilt[TCP].chksum) == (ip_sum, tcp_sum)
        checked += 1
    assert checked > 50


def test_handshake_numbers_are_consistent(capture):
    # The generated server's SYN-ACK should acknowledge the client's SYN + 1.
    # This generator check is stronger than the detector's flag-only tracking.
    packets, _ = capture
    syns, checked = {}, 0
    for captured_packet in packets:
        if TCP not in captured_packet:
            continue
        tcp, ip = captured_packet[TCP], captured_packet[IP]
        if tcp.flags == "S":
            syns[(ip.src, tcp.sport, ip.dst, tcp.dport)] = tcp.seq
        elif tcp.flags == "SA":
            seq = syns.get((ip.dst, tcp.dport, ip.src, tcp.sport))
            assert seq is not None and tcp.ack == (seq + 1) & 0xFFFFFFFF
            checked += 1
    assert checked > 50


def test_same_seed_gives_the_same_capture():
    # Same seed: identical packet bytes and labels. Different seed: different bytes.
    # Reproducibility lets a threshold change be compared on the same input.
    alert, labels_a = generate.build(seed=3, duration=30.0)
    b, labels_b = generate.build(seed=3, duration=30.0)
    assert [bytes(packet_info) for packet_info in alert] == [bytes(packet_info) for packet_info in b] and labels_a == labels_b
    c, _ = generate.build(seed=4, duration=30.0)
    assert [bytes(packet_info) for packet_info in alert] != [bytes(packet_info) for packet_info in c]


def test_detector_finds_the_flood_in_the_capture(capture):
    packets, labels = capture
    detector = Detector()
    for captured_packet in packets:
        detector.handle(captured_packet)
    flood = next(e for e in labels["events"] if e["kind"] == "attack" and e["rule"] == "syn_flood")
    assert any(alert.rule == "syn_flood" and alert.target in flood["targets"]
               and flood["start"] <= alert.timestamp <= flood["end"] for alert in detector.alerts)
