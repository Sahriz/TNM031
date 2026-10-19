"""Score the detector against label files.

python evaluate.py score data/test
python evaluate.py sweep data/tune --csv sweep.csv --write-config config.json

An attack counts as detected if an alert of the same rule about the same host
fires between its start and its end plus --slack seconds. Every other alert is
a false positive, except alerts about an attacked host that come after the
attack has ended; those are listed separately as late. Alerts below medium
severity are informational and not scored.
"""

import argparse
import csv
import itertools
import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from scapy.utils import PcapReader

from ids.alerts import RANK, Alert
from ids.detector import Detector
from ids.packets import PacketInfo, decode
from ids.rules import ARP_SPOOF, PORT_SCAN, RULES, SYN_FLOOD, Config

DEFAULT_CONFIG = Path(__file__).with_name("config.json")
MIN_SEVERITY = "medium"

# Threshold tuning tries 36 scan, 48 flood and six ARP settings.
# That is 90 per-rule candidates, not all combinations across the three rules.
# Separate tuning and test captures keep threshold selection out of final scoring.
GRIDS = {
    PORT_SCAN: {"window": [5, 10, 30, 60, 120, 300], "threshold": [5, 10, 15, 20, 30, 50]},
    SYN_FLOOD: {"window": [1, 2, 5, 10], "threshold": [50, 100, 200, 400],
                "min_incomplete_ratio": [0.0, 0.5, 0.8]},
    ARP_SPOOF: {"stale_after": [5, 15, 30, 60, 120, 300]},
}
# Tie-break between equally good settings: the one that alerts least readily.
CAUTIOUS = {
    PORT_SCAN: lambda parameters: (parameters["threshold"], -parameters["window"]),
    SYN_FLOOD: lambda parameters: (parameters["threshold"], parameters["min_incomplete_ratio"], -parameters["window"]),
    ARP_SPOOF: lambda parameters: (-parameters["stale_after"],),
}


@dataclass
class Tally:
    # TP = detected attack events; FN = missed attack events;
    # FP = unmatched alert records. Precision here mixes those units,
    # so it is not packet accuracy or a conventional packet-level confusion matrix.
    detected: int = 0  # attacks detected
    missed: int = 0  # attacks missed
    false_positives: int = 0  # alerts that match no attack

    def add(self, other: "Tally") -> None:
        self.detected += other.detected
        self.missed += other.missed
        self.false_positives += other.false_positives

    @property
    def precision(self) -> float:
        # Precision = TP / (TP + FP): how much the reported result is affected by
        # false alarms. With no scored findings, this code uses 1.0 by convention.
        total_findings = self.detected + self.false_positives
        if total_findings == 0:
            return 1.0
        return self.detected / total_findings

    @property
    def recall(self) -> float:
        # Recall = TP / (TP + FN): the fraction of labeled attacks we found.
        # With no labeled attacks, this code uses 1.0 by convention.
        total_attacks = self.detected + self.missed
        if total_attacks == 0:
            return 1.0
        return self.detected / total_attacks

    @property
    def f_half(self) -> float:
        """F0.5: precision counts twice as much as recall."""
        # beta=0.5 gives (1 + 0.25)PR / (0.25P + R).
        # This favors precision when choosing thresholds, prioritizing fewer
        # false alarms. It is not an accuracy percentage.
        if self.detected == 0:
            return 0.0
        precision = self.precision
        recall = self.recall
        return 1.25 * precision * recall / (0.25 * precision + recall)


@dataclass
class Outcome:
    detected: set = field(default_factory=set)         # ids of detected attacks
    false_alarms: list = field(default_factory=list)   # (alert, look-alike event or None)
    late: list = field(default_factory=list)           # (alert, attack event)
    informational: list = field(default_factory=list)


def same_subject(alert: Alert, event: dict) -> bool:
    # Match scans by their source, but floods and ARP conflicts by the victim.
    # A distributed flood may not identify one attacker, so target matching matters.
    if alert.rule == PORT_SCAN:
        return alert.actor in event["actors"]
    return alert.target in event["targets"]


def match(alerts: list[Alert], events: list[dict], slack: float = 10.0) -> Outcome:
    # Labels are used here after detection; the rules only receive traffic.
    # A hit needs the same rule and relevant host, plus onset within the event
    # or the ten-second allowance. This allowance is a scoring choice, not a
    # detection window and not the alert's hold/expiry time.
    outcome = Outcome()
    attacks = [event for event in events if event["kind"] == "attack"]
    benign = [event for event in events if event["kind"] == "benign"]
    for alert in alerts:
        if RANK[alert.severity] < RANK[MIN_SEVERITY]:
            # Low-severity alerts are listed but excluded from
            # both hits and false positives. A low-only attack can still be missed.
            outcome.informational.append(alert)
            continue
        hit = late = None
        for event in attacks:
            if event["rule"] != alert.rule or not same_subject(alert, event):
                continue
            if event["start"] <= alert.timestamp <= event["end"] + slack:
                hit = event
                break
            if alert.timestamp > event["end"]:
                late = event
        if hit is not None:
            # A set keeps each event ID once even if several alerts match it.
            outcome.detected.add(hit["id"])
        elif late is not None:
            # Alerts after a matching attack's allowed interval are excluded too.
            # There is no upper bound on this late exclusion, so even much later
            # alerts for the same rule and subject do not count as false positives.
            outcome.late.append((alert, late))
        else:
            # Attach a possible benign lookalike for explanation, not proven cause.
            # This lookup uses rule, host and start time, not the benign end time.
            cause = None
            for event in benign:
                if event["rule"] == alert.rule and same_subject(alert, event) and event["start"] <= alert.timestamp:
                    cause = event
                    break
            outcome.false_alarms.append((alert, cause))
    return outcome


def tally(outcome: Outcome, events: list[dict], rule: str) -> Tally:
    # No true-negative population is defined here, so no classical false-positive
    # rate is calculated. Counts, precision and recall are the reported measures.
    attacks = [event for event in events if event["kind"] == "attack" and event["rule"] == rule]
    detected = sum(event["id"] in outcome.detected for event in attacks)
    return Tally(detected, len(attacks) - detected,
                 sum(alert.rule == rule for alert, _ in outcome.false_alarms))


def load_set(directory: Path) -> list[tuple[str, list[PacketInfo], dict]]:
    """Decode every capture once; a sweep replays the decoded headers many times."""
    # Paired PCAP/label files provide packets and known events.
    # Keeping decoded headers avoids repeating Scapy decoding for every threshold.
    captures = []
    for labels_path in sorted(directory.glob("*.labels.json")):
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        with PcapReader(str(labels_path.with_name(labels["pcap"]))) as reader:
            packets = [decode(captured_packet) for captured_packet in reader]
        captures.append((labels["pcap"], packets, labels))
    if not captures:
        raise SystemExit(f"no *.labels.json files in {directory}")
    return captures


def detect(packets: list[PacketInfo], config: Config, enabled_rules=RULES) -> list[Alert]:
    # A fresh Detector starts each capture with empty history. Only packets and
    # settings go in; label events are used by match() after the alerts come out.
    detector = Detector(config, enabled_rules=enabled_rules)
    for packet in packets:
        detector.handle_info(packet)
    return detector.alerts


def score(captures, config: Config, slack: float) -> None:
    # Report totals, per-subtype misses and excluded alerts for these settings.
    # Fresh synthetic seeds test new examples from the same generator; results on
    # these captures alone do not establish accuracy on recorded real traffic.
    totals = {rule: Tally() for rule in RULES}
    by_subtype: dict[tuple, list] = {}
    notes = []
    for name, packets, labels in captures:
        events = labels["events"]
        outcome = match(detect(packets, config), events, slack)
        for rule in RULES:
            totals[rule].add(tally(outcome, events, rule))
        for event in events:
            if event["kind"] == "attack":
                by_subtype.setdefault((event["rule"], event["subtype"]), []).append(
                    event["id"] in outcome.detected)
        start = labels["start"]
        for alert, cause in outcome.false_alarms:
            why = f"look-alike: {cause['subtype']}" if cause else "no labeled cause"
            notes.append(f"  false positive  {name} +{alert.timestamp - start:6.1f}s  {alert.rule}/{alert.subtype} "
                         f"actor={alert.actor} target={alert.target}  ({why})")
        for alert, event in outcome.late:
            notes.append(f"  late            {name} +{alert.timestamp - start:6.1f}s  {alert.rule}/{alert.subtype} "
                         f"target={alert.target}  ({alert.timestamp - event['end']:.0f}s after {event['subtype']} ended)")
        for alert in outcome.informational:
            notes.append(f"  informational   {name} +{alert.timestamp - start:6.1f}s  {alert.rule}/{alert.subtype} "
                         f"target={alert.target}  ({alert.severity})")

    overall = Tally()
    print(f"{'rule':<12} {'attacks':>7} {'detected':>8} {'missed':>6} {'false pos':>9} "
          f"{'precision':>9} {'recall':>6} {'F0.5':>6}")
    for rule, counts in list(totals.items()) + [("all", overall)]:
        if rule != "all":
            overall.add(counts)
        print(f"{rule:<12} {counts.detected + counts.missed:>7} {counts.detected:>8} {counts.missed:>6} {counts.false_positives:>9} "
              f"{counts.precision:>9.2f} {counts.recall:>6.2f} {counts.f_half:>6.2f}")
    print("\ndetected per attack subtype")
    for (rule, subtype), hits in sorted(by_subtype.items()):
        print(f"  {rule + '/' + subtype:<28} {sum(hits)}/{len(hits)}")
    if notes:
        print("\nalerts that matched no attack")
        print("\n".join(notes))


def pick(rule: str, results: list[tuple[dict, Tally]]) -> tuple[dict, Tally]:
    """Best F0.5, then precision. Several settings usually tie; of those, take the
    one with the most tied neighbors in the grid, since a setting at the edge of
    the good region is the first to tip over on new data."""
    # Maximize F0.5, then precision. If several candidates tie,
    # prefer one with more equally good neighboring settings, then the cautious
    # tie-break above. This is a selection heuristic, not proof of generalization.
    grid = GRIDS[rule]
    top = max((counts.f_half, counts.precision) for _, counts in results)
    tied = [(parameters, counts) for parameters, counts in results if (counts.f_half, counts.precision) == top]
    tied_positions = []
    for parameters, counts in tied:
        position = []
        for setting, choices in grid.items():
            position.append(choices.index(parameters[setting]))
        tied_positions.append(position)

    def neighbors(parameters: dict) -> int:
        # A neighbor changes one setting by one position in its candidate list.
        # Count only neighbors with the same best F0.5 and precision.
        position = []
        for setting, choices in grid.items():
            position.append(choices.index(parameters[setting]))
        neighbor_count = 0
        for dimension in range(len(position)):
            for step in (-1, 1):
                neighbor = position.copy()
                neighbor[dimension] += step
                if neighbor in tied_positions:
                    neighbor_count += 1
        return neighbor_count

    return max(tied, key=lambda result: (neighbors(result[0]), CAUTIOUS[rule](result[0])))


def sweep(captures, base: Config, slack: float, csv_path: Path | None) -> Config:
    # Grid search evaluates a fixed list of candidates for each rule independently.
    # itertools.product enumerates the combinations within one rule. replace()
    # makes a candidate configuration without changing the original settings.
    rows, best = [], {}
    for rule, grid in GRIDS.items():
        results = []
        for values in itertools.product(*grid.values()):
            parameters = dict(zip(grid, values))
            config = replace(base, **{rule: replace(getattr(base, rule), **parameters)})
            total = Tally()
            for _, packets, labels in captures:
                # Enable only the rule being tuned, replay each tuning capture,
                # then score its findings against that capture's known events.
                events = labels["events"]
                alerts = detect(packets, config, enabled_rules=(rule,))
                outcome = match(alerts, events, slack)
                total.add(tally(outcome, events, rule))
            results.append((parameters, total))
            rows.append({"rule": rule, **parameters, "detected": total.detected, "missed": total.missed,
                         "false_positives": total.false_positives, "precision": round(total.precision, 3),
                         "recall": round(total.recall, 3), "f0.5": round(total.f_half, 3)})
        best[rule] = pick(rule, results)

    tuned = base
    for rule, (parameters, total) in best.items():
        tuned = replace(tuned, **{rule: replace(getattr(tuned, rule), **parameters)})
        settings = ", ".join(f"{setting}={value}" for setting, value in parameters.items())
        print(f"{rule:<10} best F0.5 {total.f_half:.2f}  (detected {total.detected}/{total.detected + total.missed}, "
              f"false positives {total.false_positives})  {settings}")
    if csv_path:
        columns = list(dict.fromkeys(key for row in rows for key in row))
        with open(csv_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=columns, restval="")
            writer.writeheader()
            writer.writerows(rows)
        print(f"{len(rows)} settings written to {csv_path}")
    return tuned


def main() -> None:
    # "score data/test" evaluates fixed settings; "sweep data/tune" selects them.
    # Separate datasets prevent the selection step from fitting the test examples.
    # README.md uses tuning seeds 100-107 and separate test seeds 900-907.
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("score", "sweep"))
    parser.add_argument("directory", type=Path, help="folder of .pcap and .labels.json files")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--slack", type=float, default=10.0,
                        help="seconds after an attack ends in which an alert still counts")
    parser.add_argument("--csv", type=Path, help="sweep: write every setting's result")
    parser.add_argument("--write-config", type=Path, help="sweep: save the best settings")
    arguments = parser.parse_args()

    config = Config.load(arguments.config)
    captures = load_set(arguments.directory)
    if arguments.command == "score":
        score(captures, config, arguments.slack)
        return
    tuned = sweep(captures, config, arguments.slack, arguments.csv)
    if arguments.write_config:
        arguments.write_config.write_text(json.dumps(tuned.to_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"tuned settings written to {arguments.write_config}")


if __name__ == "__main__":
    main()
