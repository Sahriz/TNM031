"""Write mock captures: python -m mock.generate --out data/tune --count 8 --seed 100

Each file is <name>.pcap plus <name>.labels.json. A file holds background
traffic, one attack of each kind and all four look-alikes, at seeded random
times and intensities. The attack subtype rotates with the file index.
"""

import argparse
import json
import random
from pathlib import Path

from scapy.utils import PcapWriter

from . import attacks, lookalikes
from .background import background
from .frames import Frames
from .hosts import BASE_TIME, Network

SCANS = ("vertical", "sweep", "slow", "distributed")
FLOODS = ("single_source", "spoofed", "low_rate")
ARPS = ("mitm", "gratuitous", "quiet_host")


def build(seed: int, index: int = 0, duration: float = 420.0) -> tuple[list, dict]:
    """Returns (frames sorted by time, labels)."""
    rng = random.Random(seed)
    net = Network(rng)
    f = Frames(net, rng)
    start, end = BASE_TIME, BASE_TIME + duration
    attacker, victim, replaced, peer_client, backup_target = rng.sample(net.clients, 5)
    scan_target = rng.choice((net.web, net.files, net.dns))
    scan, flood, arp = SCANS[index % 4], FLOODS[index % 3], ARPS[(index + index // 3) % 3]

    def scan_job(t):
        if scan == "vertical":
            return attacks.vertical_scan(f, t, attacker, scan_target)
        if scan == "sweep":
            return attacks.sweep_scan(f, t, attacker)
        if scan == "slow":
            return attacks.slow_scan(f, t, end, attacker, scan_target)
        return attacks.distributed_scan(f, t, scan_target)

    def arp_job(t):
        if arp == "mitm":
            return attacks.arp_mitm(f, t, attacker, victim, net.gateway)
        target = net.printer if arp == "quiet_host" else rng.choice((net.web, net.files))
        return attacks.arp_announce(f, t, attacker, target, arp)

    jobs = [
        scan_job,
        lambda t: attacks.syn_flood(f, t, net.web, 80, flood, attacker),
        arp_job,
        lambda t: lookalikes.backup_job(f, t, net.files, backup_target),
        lambda t: lookalikes.peer_discovery(f, t, peer_client),
        lambda t: lookalikes.flash_crowd(f, t, net.web, 443),
        lambda t: lookalikes.nic_replacement(f, t, replaced),
    ]
    rng.shuffle(jobs)
    slot = (duration - 75.0) / len(jobs)
    events = []
    for i, job in enumerate(jobs):
        event = job(start + 15.0 + i * slot + rng.uniform(0, slot / 3))
        event["id"] = f"e{i + 1}"
        events.append(event)

    background(f, start, end)
    frames = sorted((p for p in f.out if p.time < end), key=lambda p: p.time)
    labels = {
        "seed": seed,
        "start": start,
        "duration": duration,
        "hosts": {h.ip: {"name": h.name, "mac": h.mac} for h in net.hosts.values()},
        "events": events,
    }
    return frames, labels


def write(stem: Path, frames: list, labels: dict) -> None:
    with PcapWriter(str(stem.with_suffix(".pcap")), linktype=1) as writer:
        for frame in frames:
            writer.write(frame)
    labels = {"pcap": stem.with_suffix(".pcap").name, **labels}
    stem.with_suffix(".labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--seed", type=int, required=True, help="seed of the first file")
    parser.add_argument("--duration", type=float, default=420.0, help="seconds per file")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    for index in range(args.count):
        frames, labels = build(args.seed + index, index, args.duration)
        stem = args.out / f"{args.out.name}_{index:02d}"
        write(stem, frames, labels)
        kinds = ", ".join(f"{e['rule']}/{e['subtype']}" for e in labels["events"] if e["kind"] == "attack")
        print(f"{stem.name}.pcap  {len(frames):6d} frames  {kinds}")


if __name__ == "__main__":
    main()
