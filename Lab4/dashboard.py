"""Export capture reports for the local React dashboard (no live capture).

python dashboard.py data/test
python dashboard.py path/to/capture.pcapng --labels path/to/labels.json
"""

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import ipaddress
import json
import math
from pathlib import Path

from ids.detector import Detector
from ids.packets import decode, SYN, ACK
from ids.alerts import RANK
from ids.rules import Config, RULES
from evaluate import match, tally, Tally
from scapy.utils import PcapReader

ROOT = Path(__file__).resolve().parent
SCHEMA = "netpulse-report-v1"


def packet_severity(packet, active_alerts):
    """Color traffic associated with a rule already active at this packet's time.

    This is detector association, not ground-truth classification. In particular,
    an ACK or unrelated connection from a flagged host must not inherit its color.
    """
    severity = "ok"
    for alert in active_alerts:
        syn = packet.kind == "tcp" and packet.flags & SYN and not packet.flags & ACK
        related = (
            alert.rule == "port_scan" and syn and alert.actor == packet.source_ip
            or alert.rule == "syn_flood" and syn and alert.target == packet.destination_ip
            and alert.evidence.get("port") == packet.destination_port
            or alert.rule == "arp_spoof" and packet.kind == "arp"
            and alert.target == packet.source_ip and alert.evidence.get("new_mac") == packet.arp_sender_mac
        )
        if related and RANK[alert.severity] > RANK[severity]:
            severity = alert.severity
    return severity


def metrics(value):
    return {"detected": value.detected, "missed": value.missed, "false_positives": value.false_positives,
            "precision": value.precision, "recall": value.recall, "f_half": value.f_half}


def evaluation(alerts, labels):
    if labels is None:
        return None
    events = labels["events"]
    outcome = match(alerts, events)
    overall, per_rule = Tally(), {}
    for rule in RULES:
        value = tally(outcome, events, rule)
        per_rule[rule] = metrics(value)
        overall.add(value)
    return {"overall": metrics(overall), "rules": per_rule,
            "detected_event_ids": sorted(outcome.detected),
            "false_positive_ids": [alert.id for alert, _ in outcome.false_alarms],
            "late_ids": [alert.id for alert, _ in outcome.late],
            "informational_ids": [alert.id for alert in outcome.informational],
            "slack": 10, "minimum_severity": "medium"}


def build_report(path, config, labels=None, interval=1.0):
    """Stream packets once; freeze detector state at each replay boundary.

    Final alert objects mutate during detection, so copying each snapshot is
    necessary: scrubbing backwards must never show evidence from the future.
    Traffic in a frame covers (previous frame time, this frame time].
    """
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("Snapshot interval must be a positive finite number")
    detector = Detector(config)
    inventory = (labels or {}).get("hosts", {})
    hosts, frames, packet_events, detection_events = {}, [], [], []
    mac_inventory = {meta["mac"]: ip for ip, meta in inventory.items() if meta.get("mac")}
    protocols, links = Counter(), Counter()
    total_packets = total_bytes = interval_bytes = 0
    start = previous = boundary = None

    def record_detections(at, active=None):
        active = detector.log.active(at) if active is None else active
        ids = [alert.id for alert in active]
        if not detection_events or detection_events[-1][1] != ids:
            event = [round(at - start, 6), ids]
            if detection_events and detection_events[-1][0] == event[0]:
                detection_events[-1] = event
            else:
                detection_events.append(event)
        return ids

    def snapshot(at):
        nonlocal interval_bytes
        frames.append({"t": round(at - start, 6), "packets_total": total_packets,
                       "bytes_total": total_bytes,
                       "alerts": deepcopy([alert.to_dict() for alert in detector.alerts]),
                       "active_ids": record_detections(at),
                       "traffic": {"packets": sum(protocols.values()), "bytes": interval_bytes,
                                   "protocols": dict(protocols),
                                   "links": [[source, destination, count]
                                             for (source, destination), count in links.most_common(100)]}})
        protocols.clear()
        links.clear()
        interval_bytes = 0

    with PcapReader(str(path)) as reader:
        for packet in reader:
            packet_info = decode(packet)
            if not math.isfinite(packet_info.timestamp) or (previous is not None and packet_info.timestamp < previous):
                raise ValueError(f"{path.name}: timestamps must be finite and in ascending order")
            if start is None:
                start = boundary = packet_info.timestamp
            while packet_info.timestamp > boundary:
                snapshot(boundary)
                boundary += interval
                if len(frames) > 20000:
                    raise ValueError("Capture exceeds 20,000 replay frames; use a larger --interval")
            size = len(packet)
            for address, direction in ((packet_info.source_ip, "sent"), (packet_info.destination_ip, "received")):
                if not address or address in ("0.0.0.0", "255.255.255.255"):
                    continue
                meta = inventory.get(address, {})
                if address not in hosts:
                    hosts[address] = {"id": address, "name": meta.get("name", address),
                                      "mac": meta.get("mac"), "known": address in inventory,
                                      "local": ipaddress.ip_address(address).is_private,
                                      "first_seen": round(packet_info.timestamp - start, 6),
                                      "sent": 0, "received": 0, "bytes": 0}
                hosts[address][direction] += 1
                hosts[address]["bytes"] += size
            if packet_info.source_ip in hosts and packet_info.destination_ip in hosts and packet_info.source_ip != packet_info.destination_ip:
                links[(packet_info.source_ip, packet_info.destination_ip)] += 1
            # ARP's claimed IP may belong to a victim. Use the actual sender's
            # known hardware identity for the visual route, including broadcasts.
            sender = packet_info.source_ip or packet_info.source_mac
            if packet_info.kind == "arp":
                sender = mac_inventory.get(packet_info.source_mac) or detector.state.mac_owner.get(packet_info.source_mac) or packet_info.source_mac
            recipient = "__broadcast" if packet_info.destination_mac == "ff:ff:ff:ff:ff:ff" else (packet_info.destination_ip or packet_info.destination_mac)
            detector.handle_info(packet_info)
            active = detector.log.active(packet_info.timestamp)
            record_detections(packet_info.timestamp, active)
            if sender and recipient:
                for address in (sender, recipient):
                    if address != "__broadcast" and address not in hosts:
                        hosts[address] = {"id": address, "name": address, "mac": address if ":" in address else None,
                                          "known": False, "local": False,
                                              "first_seen": round(packet_info.timestamp - start, 6),
                                          "sent": 0, "received": 0, "bytes": 0}
                packet_events.append([round(packet_info.timestamp - start, 6), sender, recipient, packet_info.kind,
                                      packet_severity(packet_info, active), size,
                                      packet_info.source_port, packet_info.destination_port, packet_info.flags])
            total_packets += 1
            total_bytes += size
            interval_bytes += size
            protocols[packet_info.kind] += 1
            previous = packet_info.timestamp
    if start is None:
        raise ValueError(f"{path.name}: the capture is empty")
    # Include the actual last instant, not an artificial future expiry time.
    snapshot(previous)
    for alert in detector.alerts:
        for address in (alert.actor, alert.target):
            if address and address not in hosts:
                hosts[address] = {"id": address, "name": address, "mac": address if ":" in address else None,
                                  "known": False, "local": False, "first_seen": alert.timestamp - start,
                                  "sent": 0, "received": 0, "bytes": 0}
    capture_id = path.stem + "-" + hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:8]
    return {"schema": SCHEMA, "id": capture_id, "name": path.name,
            "source": "Generated capture" if labels and "seed" in labels else "Local capture",
            "seed": (labels or {}).get("seed"), "start": start,
            "duration": round(previous - start, 6), "interval": interval,
            "packet_count": total_packets, "byte_count": total_bytes,
            "hosts": list(hosts.values()), "frames": frames,
            "packet_events": packet_events,
            "detection_events": detection_events,
            "packet_event_fields": ["t", "source", "destination", "protocol", "severity", "bytes",
                "source_port", "destination_port", "tcp_flags"],
            "alerts": [alert.to_dict() for alert in detector.alerts],
            "events": deepcopy((labels or {}).get("events", [])),
            "config": config.to_dict(), "evaluation": evaluation(detector.alerts, labels)}


def export(paths, destination, config, labels_path=None, interval=1.0):
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else []
    for path in paths:
        candidate = labels_path or path.with_suffix(".labels.json")
        labels = json.loads(candidate.read_text(encoding="utf-8")) if candidate.exists() else None
        report = build_report(path, config, labels, interval)
        filename = report["id"] + ".json"
        (destination / filename).write_text(json.dumps(report, separators=(",", ":"), allow_nan=False),
            encoding="utf-8")
        manifest = [entry for entry in manifest if entry["id"] != report["id"]]
        manifest.append({"id": report["id"], "name": report["name"], "file": filename,
                         "source": report["source"], "packet_count": report["packet_count"], "packet_stream": True,
                         "packet_ports": True, "packet_detections": True})
        print(f"{path.name}: {report['packet_count']:,} packets, {len(report['alerts'])} alerts exported", flush=True)
    manifest.sort(key=lambda item: item["name"])
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?", default=ROOT / "data" / "test")
    parser.add_argument("--out", type=Path, default=ROOT / "frontend" / "public" / "reports")
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    parser.add_argument("--labels", type=Path, help="Optional labels for a single capture")
    parser.add_argument("--interval", type=float, default=1, help="Replay interval in seconds (default 1)")
    arguments = parser.parse_args()
    if arguments.source.is_dir():
        paths = sorted(path for path in arguments.source.iterdir() if path.suffix.lower() in (".pcap", ".pcapng"))
    else:
        paths = [arguments.source]
    if not paths or any(not path.is_file() for path in paths):
        parser.error("No capture files found. Generate mock data first or supply a capture path.")
    if arguments.labels and (len(paths) != 1 or not arguments.labels.is_file()):
        parser.error("--labels requires one capture and an existing label file")
    try:
        export(paths, arguments.out, Config.load(arguments.config), arguments.labels, arguments.interval)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print("Reports ready. Start the dashboard with: npm.cmd --prefix frontend run dev")


if __name__ == "__main__":
    main()
