"""Run the detector on a capture: python run.py capture.pcap [--out alerts.jsonl]"""

import argparse
import json
from pathlib import Path

from scapy.utils import PcapReader

from ids.alerts import RANK, write_jsonl
from ids.detector import Detector
from ids.rules import Config

DEFAULT_CONFIG = Path(__file__).with_name("config.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="pcap or pcapng file")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, default=Path("alerts.jsonl"))
    parser.add_argument("--status", type=Path, help="write the final per-host status as JSON")
    args = parser.parse_args()

    first = None

    def show(alert):
        who = " ".join(f"{k}={v}" for k, v in (("actor", alert.actor), ("target", alert.target)) if v)
        print(f"[{alert.ts - first:8.2f}s] {alert.severity.upper():<6} {alert.rule}/{alert.subtype}  {who}")

    detector = Detector(Config.load(args.config), on_alert=show)
    packets = 0
    with PcapReader(str(args.pcap)) as reader:
        for pkt in reader:
            if first is None:
                first = float(pkt.time)
            detector.handle(pkt)
            packets += 1

    write_jsonl(detector.alerts, args.out)
    print(f"\n{packets} packets, {len(detector.alerts)} alerts written to {args.out}")

    status = detector.host_status()
    flagged = sorted(detector.peak, key=lambda h: -RANK[detector.peak[h]])
    if flagged:
        print("\nhost               worst     at end of capture")
        for host in flagged:
            now = status.get(host, {"status": "ok"})["status"]
            print(f"{host:<18} {detector.peak[host]:<9} {now}")
    if args.status:
        args.status.write_text(json.dumps(status, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
