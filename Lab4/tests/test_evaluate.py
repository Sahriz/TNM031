import pytest

from evaluate import Tally, match, tally
from ids.alerts import Alert


def alert(ts, rule, actor=None, target=None, severity="medium"):
    return Alert(1, ts, rule, "x", severity, actor, target)


def event(id, kind, rule, start, end, actors=(), targets=(), subtype="x"):
    return {"id": id, "kind": kind, "rule": rule, "subtype": subtype, "start": start, "end": end,
            "actors": list(actors), "targets": list(targets)}


EVENTS = [
    event("scan", "attack", "port_scan", 100, 120, actors=["10.0.0.66"], targets=["10.0.0.10"]),
    event("flood", "attack", "syn_flood", 200, 215, targets=["10.0.0.10"]),
    event("arp", "attack", "arp_spoof", 300, 340, actors=["10.0.0.66"], targets=["10.0.0.1", "10.0.0.105"]),
    event("backup", "benign", "port_scan", 50, 70, actors=["10.0.0.12"], targets=["10.0.0.105"]),
]


def test_alerts_are_matched_on_rule_host_and_time():
    out = match([alert(105, "port_scan", actor="10.0.0.66"),
                 alert(202, "syn_flood", target="10.0.0.10"),
                 alert(310, "arp_spoof", target="10.0.0.105")], EVENTS)
    assert out.detected == {"scan", "flood", "arp"} and out.false_alarms == []


def test_several_alerts_for_one_attack_count_once():
    out = match([alert(105, "port_scan", actor="10.0.0.66"), alert(118, "port_scan", actor="10.0.0.66")], EVENTS)
    assert tally(out, EVENTS, "port_scan") == Tally(tp=1, fn=0, fp=0)


def test_wrong_rule_for_a_real_attack_is_a_false_positive():
    out = match([alert(105, "syn_flood", target="10.0.0.10")], EVENTS)
    assert out.detected == set()
    assert tally(out, EVENTS, "syn_flood") == Tally(tp=0, fn=1, fp=1)
    assert tally(out, EVENTS, "port_scan") == Tally(tp=0, fn=1, fp=0)


def test_alert_on_a_lookalike_is_attributed_to_it():
    out = match([alert(60, "port_scan", actor="10.0.0.12")], EVENTS)
    [(_, cause)] = out.false_alarms
    assert cause["id"] == "backup"


def test_slack_late_and_early_alerts():
    out = match([alert(128, "port_scan", actor="10.0.0.66")], EVENTS, slack=10)
    assert out.detected == {"scan"}
    out = match([alert(180, "port_scan", actor="10.0.0.66")], EVENTS, slack=10)
    assert out.detected == set() and len(out.late) == 1 and out.false_alarms == []
    out = match([alert(90, "port_scan", actor="10.0.0.66")], EVENTS, slack=10)
    assert len(out.false_alarms) == 1


def test_low_severity_is_not_scored():
    out = match([alert(60, "arp_spoof", target="10.0.0.107", severity="low")], EVENTS)
    assert out.false_alarms == [] and len(out.informational) == 1


def test_f_half_weights_precision():
    assert Tally(tp=8, fn=2, fp=0).f_half == pytest.approx(1.25 * 0.8 / (0.25 + 0.8))
    assert Tally(tp=10, fn=0, fp=5).f_half < Tally(tp=5, fn=5, fp=0).f_half
    assert Tally(tp=0, fn=3, fp=0).f_half == 0.0
