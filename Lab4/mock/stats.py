"""Traffic statistics for comparing mock captures with real ones:
python -m mock.stats capture.pcap [--from SECONDS --to SECONDS]

Prints only counts and rates, so it is safe to run on a private capture.
"""

import argparse
from collections import Counter, defaultdict

from scapy.utils import PcapReader

from ids.packets import ACK, FIN, RST, SYN, TCP_KIND, decode


def summarize(path: str, t_from: float = 0.0, t_to: float = float("inf")) -> dict:
    kinds, flags = Counter(), Counter()
    per_second = Counter()
    syn_per_second = Counter()
    ports_per_source_second = defaultdict(set)
    first = last = None
    with PcapReader(path) as reader:
        for pkt in reader:
            p = decode(pkt)
            if first is None:
                first = p.ts
            offset = p.ts - first
            if not t_from <= offset < t_to:
                continue
            last = p.ts
            second = int(offset)
            kinds[p.kind] += 1
            per_second[second] += 1
            if p.kind != TCP_KIND:
                continue
            if p.flags & SYN:
                flags["syn_ack" if p.flags & ACK else "syn"] += 1
                if not p.flags & ACK:
                    syn_per_second[second] += 1
                    ports_per_source_second[(p.src_ip, second)].add((p.dst_ip, p.dport))
            elif p.flags & RST:
                flags["rst"] += 1
            elif p.flags & FIN:
                flags["fin"] += 1
    total = sum(kinds.values())
    duration = max((last - first - t_from) if total else 0.0, 1e-9)
    return {
        "packets": total,
        "duration": duration,
        "kinds": kinds,
        "flags": flags,
        "peak_pps": max(per_second.values(), default=0),
        "peak_syn_per_second": max(syn_per_second.values(), default=0),
        "peak_ports_per_source_second": max(map(len, ports_per_source_second.values()), default=0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pcap")
    parser.add_argument("--from", dest="t_from", type=float, default=0.0, help="seconds from the first packet")
    parser.add_argument("--to", dest="t_to", type=float, default=float("inf"))
    args = parser.parse_args()

    s = summarize(args.pcap, args.t_from, args.t_to)
    total = max(s["packets"], 1)
    print(f"packets            {s['packets']}")
    print(f"duration           {s['duration']:.1f} s")
    print(f"mean rate          {s['packets'] / s['duration']:.1f} packets/s (peak {s['peak_pps']})")
    for kind, count in s["kinds"].most_common():
        print(f"  {kind:<16} {count:7d}  {100 * count / total:5.1f} %")
    tcp = max(s["kinds"].get(TCP_KIND, 0), 1)
    for name in ("syn", "syn_ack", "rst", "fin"):
        count = s["flags"].get(name, 0)
        print(f"  tcp {name:<12} {count:7d}  {100 * count / tcp:5.1f} % of TCP")
    syn = s["flags"].get("syn", 0)
    print(f"SYN-ACK per SYN    {s['flags'].get('syn_ack', 0) / syn:.2f}" if syn else "SYN-ACK per SYN    -")
    print(f"peak SYN rate      {s['peak_syn_per_second']} /s")
    print(f"peak distinct (host, port) per source per second  {s['peak_ports_per_source_second']}")


if __name__ == "__main__":
    main()
