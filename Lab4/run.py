"""Run the detector on a capture: python run.py capture.pcap [--out alerts.jsonl]"""

# Passive, offline detection: read a saved capture and report evidence.
# It does not block traffic, prove a break-in, or measure whether a server failed.
# main() feeds packets to ids/detector.py, which updates ids/state.py and calls
# ids/rules.py. Findings are stored by ids/alerts.py.

import argparse
import json
from pathlib import Path

from scapy.utils import PcapReader

from ids.alerts import RANK, write_jsonl
from ids.detector import Detector
from ids.rules import Config

DEFAULT_CONFIG = Path(__file__).with_name("config.json")


def show_alert(alert, capture_start):
    # Display time relative to the capture's first packet for readable output.
    # The JSON file keeps the original timestamp. Actor is the suspected source;
    # target is the affected host, when those roles can be identified.
    participants = []
    if alert.actor:
        participants.append(f"actor={alert.actor}")
    if alert.target:
        participants.append(f"target={alert.target}")
    elapsed = alert.timestamp - capture_start
    print(f"[{elapsed:8.2f}s] {alert.severity.upper():<6} "
          f"{alert.rule}/{alert.subtype}  {' '.join(participants)}")


def main() -> None:
    # These arguments select the input and output files, not the detection logic.
    # Example: python run.py data/test/test_00.pcap --status status.json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="pcap or pcapng file")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, default=Path("alerts.jsonl"))
    parser.add_argument("--status", type=Path, help="write the final per-host status as JSON")
    arguments = parser.parse_args()

    # config.json supplies the actual thresholds. The fallback
    # defaults in ids/rules.py and the smaller test fixtures may be different.
    # No label file is read here: the detector is not told where attacks occur.
    detector = Detector(Config.load(arguments.config))
    capture_start = None
    packet_count = 0
    # Scapy reads one packet at a time. Our Detector makes the decisions.
    # New findings return immediately; repeated triggers update existing records.
    with PcapReader(str(arguments.pcap)) as reader:
        for captured_packet in reader:
            if capture_start is None:
                capture_start = float(captured_packet.time)
            new_alerts = detector.handle(captured_packet)
            for alert in new_alerts:
                show_alert(alert, capture_start)
            packet_count += 1

    # Save after processing so refreshed counts and peak evidence are included.
    # An alert-record count is not a count of distinct attacks; evaluate.py matches
    # records to the labeled events to measure that separately.
    write_jsonl(detector.alerts, arguments.out)
    print(f"\n{packet_count} packets, {len(detector.alerts)} alerts written to {arguments.out}")

    # "worst" is historical; "at end" uses only unexpired alerts.
    # Neither column proves that an attack is still occurring at that moment.
    status = detector.host_status()
    flagged_hosts = sorted(detector.peak, key=lambda host: RANK[detector.peak[host]], reverse=True)
    if flagged_hosts:
        print("\nhost               worst     at end of capture")
        for host in flagged_hosts:
            final_status = status.get(host, {"status": "ok"})["status"]
            print(f"{host:<18} {detector.peak[host]:<9} {final_status}")
    if arguments.status:
        arguments.status.write_text(json.dumps(status, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
