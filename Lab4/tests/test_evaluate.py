import pytest

from evaluate import Tally, match, tally
from ids.alerts import Alert

# Known alerts and events isolate matching, exclusions and score formulas from
# the detection logic.


def alert(timestamp, rule, actor=None, target=None, severity="medium"):
    return Alert(1, timestamp, rule, "x", severity, actor, target)


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
    outcome = match([alert(105, "port_scan", actor="10.0.0.66"),
                 alert(202, "syn_flood", target="10.0.0.10"),
                 alert(310, "arp_spoof", target="10.0.0.105")], EVENTS)
    assert outcome.detected == {"scan", "flood", "arp"} and outcome.false_alarms == []


def test_several_alerts_for_one_attack_count_once():
    # Event-level recall: two matching records still detect only one labeled attack.
    outcome = match([alert(105, "port_scan", actor="10.0.0.66"), alert(118, "port_scan", actor="10.0.0.66")], EVENTS)
    assert tally(outcome, EVENTS, "port_scan") == Tally(detected=1, missed=0, false_positives=0)


def test_wrong_rule_for_a_real_attack_is_a_false_positive():
    outcome = match([alert(105, "syn_flood", target="10.0.0.10")], EVENTS)
    assert outcome.detected == set()
    assert tally(outcome, EVENTS, "syn_flood") == Tally(detected=0, missed=1, false_positives=1)
    assert tally(outcome, EVENTS, "port_scan") == Tally(detected=0, missed=1, false_positives=0)


def test_alert_on_a_lookalike_is_attributed_to_it():
    outcome = match([alert(60, "port_scan", actor="10.0.0.12")], EVENTS)
    [(_, cause)] = outcome.false_alarms
    assert cause["id"] == "backup"


def test_slack_late_and_early_alerts():
    # An alert 8 seconds after the event is inside the allowance; 60 seconds after
    # is excluded as late. An alert before the event counts as a false positive.
    outcome = match([alert(128, "port_scan", actor="10.0.0.66")], EVENTS, slack=10)
    assert outcome.detected == {"scan"}
    outcome = match([alert(180, "port_scan", actor="10.0.0.66")], EVENTS, slack=10)
    assert outcome.detected == set() and len(outcome.late) == 1 and outcome.false_alarms == []
    outcome = match([alert(90, "port_scan", actor="10.0.0.66")], EVENTS, slack=10)
    assert len(outcome.false_alarms) == 1


def test_low_severity_is_not_scored():
    outcome = match([alert(60, "arp_spoof", target="10.0.0.107", severity="low")], EVENTS)
    assert outcome.false_alarms == [] and len(outcome.informational) == 1


def test_f_half_weights_precision():
    # A detector with fewer false alarms can win even with more missed attacks.
    # This is the tradeoff used to select thresholds, not a guarantee of quality.
    assert Tally(detected=8, missed=2, false_positives=0).f_half == pytest.approx(1.25 * 0.8 / (0.25 + 0.8))
    assert Tally(detected=10, missed=0, false_positives=5).f_half < Tally(detected=5, missed=5, false_positives=0).f_half
    assert Tally(detected=0, missed=3, false_positives=0).f_half == 0.0
