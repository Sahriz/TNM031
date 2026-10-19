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

# Synthetic data supplies known attack times and benign lookalikes.
# It is reproducible test input, not proof that the detector handles real networks.
# Frames are written to files; these functions do not transmit an attack.


def build(seed: int, index: int = 0, duration: float = 420.0) -> tuple[list, dict]:
    """Returns (frames sorted by time, labels)."""
    # A seed reproduces the random choices. Changing the seed gives a different
    # example; the file index rotates attack variants so the set covers more cases.
    # Network defines hosts; Frames builds packets; attacks/lookalikes add events.
    random_generator = random.Random(seed)
    network = Network(random_generator)
    frame_builder = Frames(network, random_generator)
    start, end = BASE_TIME, BASE_TIME + duration
    attacker, victim, replaced, peer_client, backup_target = random_generator.sample(network.clients, 5)
    scan_target = random_generator.choice((network.web, network.files, network.dns))
    scan, flood, arp = SCANS[index % 4], FLOODS[index % 3], ARPS[(index + index // 3) % 3]

    def scan_job(timestamp):
        if scan == "vertical":
            return attacks.vertical_scan(frame_builder, timestamp, attacker, scan_target)
        if scan == "sweep":
            return attacks.sweep_scan(frame_builder, timestamp, attacker)
        if scan == "slow":
            return attacks.slow_scan(frame_builder, timestamp, end, attacker, scan_target)
        return attacks.distributed_scan(frame_builder, timestamp, scan_target)

    def arp_job(timestamp):
        if arp == "mitm":
            return attacks.arp_mitm(frame_builder, timestamp, attacker, victim, network.gateway)
        target = network.printer if arp == "quiet_host" else random_generator.choice((network.web, network.files))
        return attacks.arp_announce(frame_builder, timestamp, attacker, target, arp)

    jobs = [
        # One attack of each rule plus four benign lookalikes. Each callable takes
        # its scheduled timestamp, adds packets and returns an event description.
        scan_job,
        lambda timestamp: attacks.syn_flood(frame_builder, timestamp, network.web, 80, flood, attacker),
        arp_job,
        lambda timestamp: lookalikes.backup_job(frame_builder, timestamp, network.files, backup_target),
        lambda timestamp: lookalikes.peer_discovery(frame_builder, timestamp, peer_client),
        lambda timestamp: lookalikes.flash_crowd(frame_builder, timestamp, network.web, 443),
        lambda timestamp: lookalikes.nic_replacement(frame_builder, timestamp, replaced),
    ]
    random_generator.shuffle(jobs)
    slot = (duration - 75.0) / len(jobs)
    events = []
    for index, job in enumerate(jobs):
        event = job(start + 15.0 + index * slot + random_generator.uniform(0, slot / 3))
        event["id"] = f"e{index + 1}"
        events.append(event)

    # Plan events first so a replaced NIC's downtime is known to background().
    # Jobs add packets out of order; sorting below restores capture-time order.
    background(frame_builder, start, end)
    frames = sorted((packet for packet in frame_builder.out if packet.time < end), key=lambda packet: packet.time)
    labels = {
        # Labels describe intended events, participants and timing.
        # run.py never reads them; evaluate.py uses them to check the detector.
        "seed": seed,
        "start": start,
        "duration": duration,
        "hosts": {host.ip: {"name": host.name, "mac": host.mac} for host in network.hosts.values()},
        "events": events,
    }
    return frames, labels


def write(stem: Path, frames: list, labels: dict) -> None:
    # The PCAP contains Ethernet frames, and the adjacent JSON
    # contains ground truth. Scapy serializes packets and computes unset checksums.
    # Ethernet linktype lets readers such as Wireshark decode the packet layers.
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
    arguments = parser.parse_args()

    # Each file uses a different seed. README.md creates separate tuning and test
    # folders; separation reduces direct tuning to test examples but both still
    # share this generator and its assumptions.
    arguments.out.mkdir(parents=True, exist_ok=True)
    for index in range(arguments.count):
        frames, labels = build(arguments.seed + index, index, arguments.duration)
        stem = arguments.out / f"{arguments.out.name}_{index:02d}"
        write(stem, frames, labels)
        kinds = ", ".join(f"{event['rule']}/{event['subtype']}" for event in labels["events"] if event["kind"] == "attack")
        print(f"{stem.name}.pcap  {len(frames):6d} frames  {kinds}")


if __name__ == "__main__":
    main()
