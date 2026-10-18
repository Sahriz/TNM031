import json

import pytest

from ids.detector import Detector
from ids.packets import ACK, SYN
from ids.rules import Config
from util import ATTACKER_MAC, GATEWAY_MAC, NEW_MAC, arp, handshake, refused, tcp

ATTACKER, SERVER, GATEWAY = "10.0.0.66", "10.0.0.10", "10.0.0.1"


def config(**sections) -> Config:
    return Config.from_dict(sections)


@pytest.fixture
def detector():
    return Detector(config(port_scan={"window": 10, "threshold": 20},
                           syn_flood={"window": 5, "threshold": 100, "min_incomplete_ratio": 0.5},
                           arp_spoof={"stale_after": 30}))


# --- port scan ---

def test_scan_of_closed_ports(detector):
    for port in range(1, 41):
        refused(detector, port * 0.05, ATTACKER, SERVER, 40000 + port, port)
    [alert] = detector.alerts
    assert (alert.rule, alert.subtype, alert.severity) == ("port_scan", "portscan", "medium")
    assert (alert.actor, alert.target) == (ATTACKER, SERVER)
    assert alert.ts == pytest.approx(20 * 0.05)          # fires on the 20th distinct port
    assert alert.evidence["distinct_targets"] == 40      # and keeps counting
    assert alert.count == 21


def test_unanswered_probes_count_as_failed(detector):
    for port in range(1, 21):
        detector.handle_info(tcp(port * 0.05, ATTACKER, SERVER, 40000 + port, port, SYN))
    assert len(detector.alerts) == 1


def test_sweep_across_hosts(detector):
    for n in range(1, 31):
        refused(detector, n * 0.05, ATTACKER, f"10.0.1.{n}", 40000 + n, 445)
    [alert] = detector.alerts
    assert (alert.subtype, alert.target) == ("portsweep", None)
    assert alert.evidence["sample_ports"] == [445]


def test_completed_connections_are_not_a_scan(detector):
    for port in range(1, 201):
        handshake(detector, port * 0.05, "10.0.0.12", "10.0.0.105", 40000 + port, 20000 + port)
    assert detector.alerts == []


def test_repeating_one_closed_port_is_not_a_scan(detector):
    for i in range(50):
        refused(detector, i * 0.05, ATTACKER, SERVER, 40000 + i, 8080)
    assert detector.alerts == []


def test_slow_scan_stays_under_the_window(detector):
    for port in range(1, 41):
        refused(detector, port * 2.0, ATTACKER, SERVER, 40000 + port, port)  # 5 ports per 10 s
    assert detector.alerts == []


def test_scan_allowlist():
    detector = Detector(config(port_scan={"threshold": 20}, allowlist={"port_scan": [ATTACKER]}))
    for port in range(1, 41):
        refused(detector, port * 0.05, ATTACKER, SERVER, 40000 + port, port)
    assert detector.alerts == []


# --- SYN flood ---

def test_flood_from_many_sources(detector):
    for i in range(300):
        detector.handle_info(tcp(i * 0.005, f"45.1.{i // 250}.{i % 250 + 1}", SERVER, 1024 + i, 80, SYN))
    [alert] = detector.alerts
    assert (alert.rule, alert.subtype, alert.severity) == ("syn_flood", "many_sources", "high")
    assert (alert.actor, alert.target) == (None, SERVER)
    assert alert.evidence["port"] == 80 and alert.evidence["syn_count"] == 300


def test_flood_from_one_source_names_the_actor(detector):
    for i in range(300):
        detector.handle_info(tcp(i * 0.005, ATTACKER, SERVER, 1024 + i, 80, SYN))
    [alert] = detector.alerts
    assert (alert.subtype, alert.actor) == ("single_source", ATTACKER)


def test_flood_with_fixed_source_port(detector):
    for i in range(300):
        detector.handle_info(tcp(i * 0.005, ATTACKER, SERVER, 1234, 80, SYN))
    assert [a.rule for a in detector.alerts] == ["syn_flood"]


def test_burst_of_completed_connections_is_not_a_flood(detector):
    for i in range(300):
        handshake(detector, i * 0.005, f"45.1.0.{i % 250 + 1}", SERVER, 1024 + i, 443)
    assert detector.alerts == []


def test_rate_only_rule_flags_the_same_burst():
    detector = Detector(config(syn_flood={"threshold": 100, "min_incomplete_ratio": 0.0}))
    for i in range(300):
        handshake(detector, i * 0.005, f"45.1.0.{i % 250 + 1}", SERVER, 1024 + i, 443)
    assert [a.rule for a in detector.alerts] == ["syn_flood"]


def test_fast_scan_is_not_reported_as_a_flood(detector):
    for port in range(1, 401):
        refused(detector, port * 0.005, ATTACKER, SERVER, 40000 + port, port)
    assert [a.rule for a in detector.alerts] == ["port_scan"]


def test_flood_below_the_rate_threshold(detector):
    for i in range(300):
        detector.handle_info(tcp(i * 0.1, f"45.1.0.{i % 250 + 1}", SERVER, 1024 + i, 80, SYN))  # 50 per 5 s
    assert detector.alerts == []


# --- ARP spoofing ---

def learn_gateway(detector):
    detector.handle_info(arp(0.0, GATEWAY, GATEWAY_MAC))
    detector.handle_info(arp(0.1, ATTACKER, ATTACKER_MAC))


def test_changed_address_while_the_owner_is_still_active(detector):
    learn_gateway(detector)
    detector.handle_info(tcp(9.0, "8.8.8.8", "10.0.0.105", 443, 50000, ACK, src_mac=GATEWAY_MAC))
    detector.handle_info(arp(10.0, GATEWAY, ATTACKER_MAC))
    [alert] = detector.alerts
    assert (alert.rule, alert.subtype, alert.severity) == ("arp_spoof", "changed_address", "medium")
    assert (alert.actor, alert.target) == (ATTACKER, GATEWAY)
    assert alert.evidence["old_mac"] == GATEWAY_MAC and alert.evidence["new_mac"] == ATTACKER_MAC


def test_flip_flop_escalates_to_high(detector):
    learn_gateway(detector)
    detector.handle_info(arp(10.0, GATEWAY, ATTACKER_MAC))
    detector.handle_info(arp(12.0, GATEWAY, GATEWAY_MAC))   # the real gateway answers
    detector.handle_info(arp(14.0, GATEWAY, ATTACKER_MAC))  # poisoned again
    detector.handle_info(arp(16.0, GATEWAY, GATEWAY_MAC))
    detector.handle_info(arp(18.0, GATEWAY, ATTACKER_MAC))
    assert [(a.subtype, a.severity) for a in detector.alerts] == [
        ("changed_address", "medium"), ("flip_flop", "high")]
    assert detector.alerts[1].count == 3  # later flips extend the same alert


def test_replaced_nic_is_only_informational(detector):
    detector.handle_info(arp(0.0, "10.0.0.107", "aa:aa:aa:aa:aa:07"))
    detector.handle_info(arp(90.0, "10.0.0.107", NEW_MAC))  # old card silent for 90 s
    [alert] = detector.alerts
    assert (alert.subtype, alert.severity) == ("changed_address", "low")
    detector.handle_info(arp(200.0, "10.0.0.107", NEW_MAC))
    assert len(detector.alerts) == 1


def test_arp_probe_and_repeats_are_ignored(detector):
    learn_gateway(detector)
    detector.handle_info(arp(5.0, "0.0.0.0", NEW_MAC))
    detector.handle_info(arp(6.0, GATEWAY, GATEWAY_MAC))
    assert detector.alerts == []


# --- alerts and host status ---

def test_rules_fire_independently_for_the_same_host(detector):
    learn_gateway(detector)
    for port in range(1, 41):
        refused(detector, 1 + port * 0.05, ATTACKER, SERVER, 40000 + port, port)
    detector.handle_info(arp(5.0, GATEWAY, ATTACKER_MAC))
    assert sorted(a.rule for a in detector.alerts) == ["arp_spoof", "port_scan"]
    status = detector.host_status()
    assert status[ATTACKER]["status"] == "medium"
    assert {a["rule"] for a in status[ATTACKER]["alerts"]} == {"arp_spoof", "port_scan"}


def test_status_is_the_most_severe_active_alert_and_expires(detector):
    learn_gateway(detector)
    for port in range(1, 41):
        refused(detector, 1 + port * 0.05, ATTACKER, SERVER, 40000 + port, port)
    for i in range(300):
        detector.handle_info(tcp(4 + i * 0.005, ATTACKER, SERVER, 1024 + i, 80, SYN))
    assert detector.host_status()[SERVER]["status"] == "high"
    assert detector.host_status()[ATTACKER]["status"] == "high"
    assert detector.host_status()[GATEWAY]["status"] == "ok"
    later = detector.host_status(now=500.0)
    assert later[ATTACKER]["status"] == "ok" and later[ATTACKER]["alerts"] == []
    assert detector.peak[SERVER] == "high"


def test_new_alert_after_the_old_one_expired(detector):
    for round_start in (0.0, 300.0):
        for port in range(1, 31):
            refused(detector, round_start + port * 0.05, ATTACKER, SERVER, 40000 + port, port)
    assert len(detector.alerts) == 2


def test_alert_serializes_to_json(detector):
    for port in range(1, 31):
        refused(detector, port * 0.05, ATTACKER, SERVER, 40000 + port, port)
    record = json.loads(json.dumps(detector.alerts[0].to_dict()))
    assert {"id", "ts", "rule", "subtype", "severity", "actor", "target", "evidence"} <= record.keys()
    assert record["active_until"] > record["last_seen"] >= record["ts"]


def test_unknown_config_key_is_rejected():
    with pytest.raises(TypeError):
        Config.from_dict({"port_scan": {"treshold": 5}})
