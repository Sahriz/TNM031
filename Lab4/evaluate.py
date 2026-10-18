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

GRIDS = {
    PORT_SCAN: {"window": [5, 10, 30, 60, 120, 300], "threshold": [5, 10, 15, 20, 30, 50]},
    SYN_FLOOD: {"window": [1, 2, 5, 10], "threshold": [50, 100, 200, 400],
                "min_incomplete_ratio": [0.0, 0.5, 0.8]},
    ARP_SPOOF: {"stale_after": [5, 15, 30, 60, 120, 300]},
}
# Tie-break between equally good settings: the one that alerts least readily.
CAUTIOUS = {
    PORT_SCAN: lambda p: (p["threshold"], -p["window"]),
    SYN_FLOOD: lambda p: (p["threshold"], p["min_incomplete_ratio"], -p["window"]),
    ARP_SPOOF: lambda p: (-p["stale_after"],),
}


@dataclass
class Tally:
    tp: int = 0  # attacks detected
    fn: int = 0  # attacks missed
    fp: int = 0  # alerts that match no attack

    def __iadd__(self, other: "Tally") -> "Tally":
        self.tp, self.fn, self.fp = self.tp + other.tp, self.fn + other.fn, self.fp + other.fp
        return self

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f_half(self) -> float:
        """F0.5: precision counts twice as much as recall."""
        p, r = self.precision, self.recall
        return 1.25 * p * r / (0.25 * p + r) if self.tp else 0.0


@dataclass
class Outcome:
    detected: set = field(default_factory=set)         # ids of detected attacks
    false_alarms: list = field(default_factory=list)   # (alert, look-alike event or None)
    late: list = field(default_factory=list)           # (alert, attack event)
    informational: list = field(default_factory=list)


def same_subject(alert: Alert, event: dict) -> bool:
    if alert.rule == PORT_SCAN:
        return alert.actor in event["actors"]
    return alert.target in event["targets"]


def match(alerts: list[Alert], events: list[dict], slack: float = 10.0) -> Outcome:
    out = Outcome()
    attacks = [e for e in events if e["kind"] == "attack"]
    benign = [e for e in events if e["kind"] == "benign"]
    for alert in alerts:
        if RANK[alert.severity] < RANK[MIN_SEVERITY]:
            out.informational.append(alert)
            continue
        hit = late = None
        for event in attacks:
            if event["rule"] != alert.rule or not same_subject(alert, event):
                continue
            if event["start"] <= alert.ts <= event["end"] + slack:
                hit = event
                break
            if alert.ts > event["end"]:
                late = event
        if hit is not None:
            out.detected.add(hit["id"])
        elif late is not None:
            out.late.append((alert, late))
        else:
            cause = next((e for e in benign if e["rule"] == alert.rule and same_subject(alert, e)
                          and e["start"] <= alert.ts), None)
            out.false_alarms.append((alert, cause))
    return out


def tally(outcome: Outcome, events: list[dict], rule: str) -> Tally:
    attacks = [e for e in events if e["kind"] == "attack" and e["rule"] == rule]
    detected = sum(e["id"] in outcome.detected for e in attacks)
    return Tally(detected, len(attacks) - detected,
                 sum(alert.rule == rule for alert, _ in outcome.false_alarms))


def load_set(directory: Path) -> list[tuple[str, list[PacketInfo], dict]]:
    """Decode every capture once; a sweep replays the decoded headers many times."""
    captures = []
    for labels_path in sorted(directory.glob("*.labels.json")):
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        with PcapReader(str(labels_path.with_name(labels["pcap"]))) as reader:
            packets = [decode(pkt) for pkt in reader]
        captures.append((labels["pcap"], packets, labels))
    if not captures:
        raise SystemExit(f"no *.labels.json files in {directory}")
    return captures


def detect(packets: list[PacketInfo], config: Config, enabled=RULES) -> list[Alert]:
    detector = Detector(config, enabled=enabled)
    for packet in packets:
        detector.handle_info(packet)
    return detector.alerts


def score(captures, config: Config, slack: float) -> None:
    totals = {rule: Tally() for rule in RULES}
    by_subtype: dict[tuple, list] = {}
    notes = []
    for name, packets, labels in captures:
        events = labels["events"]
        outcome = match(detect(packets, config), events, slack)
        for rule in RULES:
            totals[rule] += tally(outcome, events, rule)
        for event in events:
            if event["kind"] == "attack":
                by_subtype.setdefault((event["rule"], event["subtype"]), []).append(
                    event["id"] in outcome.detected)
        start = labels["start"]
        for alert, cause in outcome.false_alarms:
            why = f"look-alike: {cause['subtype']}" if cause else "no labeled cause"
            notes.append(f"  false positive  {name} +{alert.ts - start:6.1f}s  {alert.rule}/{alert.subtype} "
                         f"actor={alert.actor} target={alert.target}  ({why})")
        for alert, event in outcome.late:
            notes.append(f"  late            {name} +{alert.ts - start:6.1f}s  {alert.rule}/{alert.subtype} "
                         f"target={alert.target}  ({alert.ts - event['end']:.0f}s after {event['subtype']} ended)")
        for alert in outcome.informational:
            notes.append(f"  informational   {name} +{alert.ts - start:6.1f}s  {alert.rule}/{alert.subtype} "
                         f"target={alert.target}  ({alert.severity})")

    overall = Tally()
    print(f"{'rule':<12} {'attacks':>7} {'detected':>8} {'missed':>6} {'false pos':>9} "
          f"{'precision':>9} {'recall':>6} {'F0.5':>6}")
    for rule, t in list(totals.items()) + [("all", overall)]:
        if rule != "all":
            overall += t
        print(f"{rule:<12} {t.tp + t.fn:>7} {t.tp:>8} {t.fn:>6} {t.fp:>9} "
              f"{t.precision:>9.2f} {t.recall:>6.2f} {t.f_half:>6.2f}")
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
    grid = GRIDS[rule]
    top = max((t.f_half, t.precision) for _, t in results)
    tied = [(params, t) for params, t in results if (t.f_half, t.precision) == top]
    cells = {tuple(grid[k].index(params[k]) for k in grid) for params, _ in tied}

    def neighbors(params: dict) -> int:
        cell = tuple(grid[k].index(params[k]) for k in grid)
        return sum(cell[:i] + (cell[i] + step,) + cell[i + 1:] in cells
                   for i in range(len(cell)) for step in (-1, 1))

    return max(tied, key=lambda r: (neighbors(r[0]), CAUTIOUS[rule](r[0])))


def sweep(captures, base: Config, slack: float, csv_path: Path | None) -> Config:
    rows, best = [], {}
    for rule, grid in GRIDS.items():
        results = []
        for values in itertools.product(*grid.values()):
            params = dict(zip(grid, values))
            config = replace(base, **{rule: replace(getattr(base, rule), **params)})
            total = Tally()
            for _, packets, labels in captures:
                events = labels["events"]
                total += tally(match(detect(packets, config, enabled=(rule,)), events, slack), events, rule)
            results.append((params, total))
            rows.append({"rule": rule, **params, "detected": total.tp, "missed": total.fn,
                         "false_positives": total.fp, "precision": round(total.precision, 3),
                         "recall": round(total.recall, 3), "f0.5": round(total.f_half, 3)})
        best[rule] = pick(rule, results)

    tuned = base
    for rule, (params, total) in best.items():
        tuned = replace(tuned, **{rule: replace(getattr(tuned, rule), **params)})
        settings = ", ".join(f"{k}={v}" for k, v in params.items())
        print(f"{rule:<10} best F0.5 {total.f_half:.2f}  (detected {total.tp}/{total.tp + total.fn}, "
              f"false positives {total.fp})  {settings}")
    if csv_path:
        columns = list(dict.fromkeys(key for row in rows for key in row))
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, restval="")
            writer.writeheader()
            writer.writerows(rows)
        print(f"{len(rows)} settings written to {csv_path}")
    return tuned


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("score", "sweep"))
    parser.add_argument("directory", type=Path, help="folder of .pcap and .labels.json files")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--slack", type=float, default=10.0,
                        help="seconds after an attack ends in which an alert still counts")
    parser.add_argument("--csv", type=Path, help="sweep: write every setting's result")
    parser.add_argument("--write-config", type=Path, help="sweep: save the best settings")
    args = parser.parse_args()

    config = Config.load(args.config)
    captures = load_set(args.directory)
    if args.command == "score":
        score(captures, config, args.slack)
        return
    tuned = sweep(captures, config, args.slack, args.csv)
    if args.write_config:
        args.write_config.write_text(json.dumps(tuned.to_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"tuned settings written to {args.write_config}")


if __name__ == "__main__":
    main()
