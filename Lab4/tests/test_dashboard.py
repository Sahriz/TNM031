"""The dashboard must preserve the detector's timing and scoring semantics."""
import json

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.utils import wrpcap

from dashboard import build_report, export, packet_severity
from ids.alerts import Alert
from ids.packets import PacketInfo, SYN, ACK
from ids.rules import Config


def capture(tmp_path, times=(0, .2, .3, 1.2, 1.3, 8)):
    packets = []
    for i, t in enumerate(times):
        captured_packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=40000 + i, dport=80, flags="S")
        captured_packet.time = 100 + t
        packets.append(captured_packet)
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def config():
    return Config.from_dict({"syn_flood": {"threshold": 2, "window": 1, "hold": 2}})


def test_replay_freezes_evidence_and_does_not_leak_future_alerts(tmp_path, config):
    report = build_report(capture(tmp_path), config)
    assert report["frames"][0]["alerts"] == []
    first = report["frames"][1]["alerts"][0]
    final = report["alerts"][0]
    assert first["count"] < final["count"]
    assert first["last_seen"] < final["last_seen"]
    assert report["frames"][1]["active_ids"] == [first["id"]]
    assert report["frames"][5]["active_ids"] == []
    assert report["frames"][5]["alerts"]  # expired alerts remain inspectable


def test_packet_bins_and_hosts_account_for_capture(tmp_path, config):
    report = build_report(capture(tmp_path), config)
    assert sum(f["traffic"]["packets"] for f in report["frames"]) == report["packet_count"] == 6
    assert sum(f["traffic"]["bytes"] for f in report["frames"]) == report["byte_count"]
    assert report["frames"][-1]["packets_total"] == 6
    assert report["duration"] == 8
    assert [h["sent"] for h in report["hosts"]] == [6, 0]
    assert report["evaluation"] is None
    json.dumps(report, allow_nan=False)


def test_labels_are_evaluated_using_existing_matching(tmp_path, config):
    labels = {"seed": 3, "events": [{"id": "attack1", "kind": "attack", "rule": "syn_flood", "subtype": "single_source",
                                   "start": 100, "end": 102, "actors": ["10.0.0.2"], "targets": ["10.0.0.3"]}]}
    report = build_report(capture(tmp_path), config, labels)
    assert report["evaluation"]["overall"]["detected"] == 1
    assert report["evaluation"]["overall"]["false_positives"] == 0
    assert report["evaluation"]["detected_event_ids"] == ["attack1"]
    assert report["source"] == "Generated capture"


def test_manifest_updates_without_duplicate_entries(tmp_path, config):
    path = capture(tmp_path)
    outcome = tmp_path / "reports"
    export([path], outcome, config)
    export([path], outcome, config)
    index = json.loads((outcome / "index.json").read_text())
    assert len(index) == 1
    assert (outcome / index[0]["file"]).exists()


@pytest.mark.parametrize("interval", [0, -1, float("nan")])
def test_invalid_interval_rejected(tmp_path, config, interval):
    with pytest.raises(ValueError, match="positive finite"):
        build_report(capture(tmp_path), config, interval=interval)


def test_out_of_order_packets_rejected(tmp_path, config):
    with pytest.raises(ValueError, match="ascending"):
        build_report(capture(tmp_path, times=(1, 0)), config)


def test_one_packet_capture_has_a_valid_zero_time_snapshot(tmp_path, config):
    report = build_report(capture(tmp_path, times=(0,)), config)
    assert len(report["frames"]) == 1
    assert report["frames"][0]["t"] == 0
    assert report["duration"] == 0


def test_packet_stream_preserves_subsecond_timing_and_bidirectional_traffic(tmp_path, config):
    request = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:03") / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=40000, dport=80, flags="S")
    response = Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:02") / IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=80, dport=40000, flags="SA")
    request.time, response.time = 100, 100.123456
    path = tmp_path / "duplex.pcap"
    wrpcap(str(path), [request, response])
    report = build_report(path, config)
    assert report["packet_events"] == [[0, "10.0.0.2", "10.0.0.3", "tcp", "ok", len(request), 40000, 80, SYN],
                                       [.123456, "10.0.0.3", "10.0.0.2", "tcp", "ok", len(response), 80, 40000, SYN | ACK]]
    assert report["frames"][0]["traffic"]["links"] == [["10.0.0.2", "10.0.0.3", 1]]
    assert report["frames"][-1]["traffic"]["links"] == [["10.0.0.3", "10.0.0.2", 1]]


def test_packet_colors_do_not_leak_future_detection(tmp_path, config):
    report = build_report(capture(tmp_path), config)
    events = report["packet_events"]
    assert events[0][4] == "ok"
    assert events[1][4] == "high"  # the second SYN reaches the configured threshold
    assert events[-1][4] == "ok"  # previous detection expired
    assert report["detection_events"][0] == [0, []]
    assert report["detection_events"][1] == [.2, [report["alerts"][0]["id"]]]
    assert report["detection_events"][-1][1] == []


@pytest.mark.parametrize("kind,flags,port,expected", [
    ("tcp", SYN, 80, "high"), ("tcp", SYN | ACK, 80, "ok"),
    ("tcp", ACK, 80, "ok"), ("tcp", SYN, 443, "ok"), ("udp", 0, 80, "ok")])
def test_threat_color_only_matches_related_traffic(kind, flags, port, expected):
    flood = Alert(1, 0, "syn_flood", "single_source", "high", "10.0.0.2", "10.0.0.3", {"port": 80})
    packet = PacketInfo(0, kind, source_ip="10.0.0.2", destination_ip="10.0.0.3", destination_port=port, flags=flags)
    assert packet_severity(packet, [flood]) == expected


def test_arp_stream_uses_actual_sender_instead_of_spoofed_ip(tmp_path, config):
    victim, attacker = "02:00:00:00:00:01", "02:00:00:00:00:02"
    packets = [Ether(src=victim, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=victim, psrc="10.0.0.1", pdst="10.0.0.3"),
               Ether(src=attacker, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=attacker, psrc="10.0.0.1", pdst="10.0.0.3")]
    for i, packet in enumerate(packets):
        packet.time = 100 + i
    path = tmp_path / "arp.pcap"
    wrpcap(str(path), packets)
    labels = {"events": [], "hosts": {"10.0.0.1": {"name": "gateway", "mac": victim}, "10.0.0.2": {"name": "client", "mac": attacker}}}
    events = build_report(path, config, labels)["packet_events"]
    assert events[1][1:5] == ["10.0.0.2", "__broadcast", "arp", "medium"]
