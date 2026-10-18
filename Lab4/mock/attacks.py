"""Attack traffic. Every function adds frames and returns the label for what it added."""

from .frames import BROADCAST, MSS_ONLY, Frames
from .hosts import SWEEP_SUBNET, Host

BACKLOG = 256  # SYNs a flooded server still answers before its queue is full


def label(kind: str, rule: str, subtype: str, actors: list, targets: list,
          start: float, end: float, **params) -> dict:
    return {"kind": kind, "rule": rule, "subtype": subtype, "actors": actors, "targets": targets,
            "start": round(start, 6), "end": round(end, 6), "params": params}


def _probe(f: Frames, t: float, src: str, dst: str, port: int, answer: str) -> None:
    """One SYN scan probe. answer: 'open' (SYN-ACK, then the scanner resets),
    'closed' (RST) or 'filtered' (nothing)."""
    sport = f.rng.randrange(32768, 61000)
    seq = f.rng.getrandbits(32)
    f.tcp(t, src, dst, sport, port, "S", seq=seq, options=MSS_ONLY)
    if answer == "filtered":
        return
    reply_at = t + f.rtt(src, dst)
    if answer == "open":
        f.tcp(reply_at, dst, src, port, sport, "SA", seq=f.rng.getrandbits(32), ack=seq + 1, options=MSS_ONLY)
        f.tcp(reply_at + 0.0003, src, dst, sport, port, "R", seq=seq + 1)
    else:
        f.tcp(reply_at, dst, src, port, sport, "RA", ack=seq + 1)


def _answer(f: Frames, target: Host, port: int, filtered: float) -> str:
    if port in target.open_ports:
        return "open"
    return "filtered" if f.rng.random() < filtered else "closed"


def vertical_scan(f: Frames, t0: float, attacker: Host, target: Host) -> dict:
    """Many ports on one host, fast."""
    rng = f.rng
    count, rate, filtered = rng.randint(100, 1000), rng.uniform(50, 400), rng.uniform(0, 0.3)
    ports = set(rng.sample(range(1, 10001), count)) | set(target.open_ports)
    t = t0
    for port in rng.sample(sorted(ports), len(ports)):
        _probe(f, t, attacker.ip, target.ip, port, _answer(f, target, port, filtered))
        t += rng.expovariate(rate)
    return label("attack", "port_scan", "vertical", [attacker.ip], [target.ip], t0, t,
                 ports=len(ports), rate=round(rate, 1))


def slow_scan(f: Frames, t0: float, t_end: float, attacker: Host, target: Host) -> dict:
    """A few seconds between probes, to stay under rate thresholds."""
    rng = f.rng
    gap = rng.uniform(1.5, 5.0)
    count = min(rng.randint(40, 90), int((t_end - t0 - 5) / gap))
    t = t0
    for port in rng.sample(range(1, 10001), count):
        _probe(f, t, attacker.ip, target.ip, port, _answer(f, target, port, 0.1))
        t += rng.uniform(0.5 * gap, 1.5 * gap)
    return label("attack", "port_scan", "slow", [attacker.ip], [target.ip], t0, t,
                 ports=count, mean_gap=round(gap, 2))


def sweep_scan(f: Frames, t0: float, attacker: Host) -> dict:
    """One or two ports across a whole subnet."""
    rng = f.rng
    ports = rng.choice(([445], [22], [3389], [22, 3389]))
    rate = rng.uniform(40, 200)
    alive = set(rng.sample(range(1, 255), 25))
    t = t0
    for n in rng.sample(range(1, 255), 254):
        for port in ports:
            answer = rng.choice(("open", "closed")) if n in alive else "filtered"
            _probe(f, t, attacker.ip, f"{SWEEP_SUBNET}{n}", port, answer)
            t += rng.expovariate(rate)
    return label("attack", "port_scan", "sweep", [attacker.ip], [f"{SWEEP_SUBNET}0/24"], t0, t,
                 ports=ports, rate=round(rate, 1))


def distributed_scan(f: Frames, t0: float, target: Host) -> dict:
    """Many sources, each probing only a handful of ports on the same host."""
    rng = f.rng
    sources = [f.net.random_public_ip() for _ in range(rng.randint(8, 15))]
    rate = rng.uniform(5, 30)
    probes = [(src, port) for src in sources
              for port in rng.sample(range(1, 10001), rng.randint(5, 12))]
    rng.shuffle(probes)
    t = t0
    for src, port in probes:
        _probe(f, t, src, target.ip, port, _answer(f, target, port, 0.1))
        t += rng.expovariate(rate)
    return label("attack", "port_scan", "distributed", sources, [target.ip], t0, t,
                 sources=len(sources), probes=len(probes), rate=round(rate, 1))


def syn_flood(f: Frames, t0: float, target: Host, port: int, subtype: str,
              attacker: Host | None = None) -> dict:
    """subtype: 'single_source' (attacker's own address), 'spoofed' (random
    source addresses) or 'low_rate' (spoofed, slow enough to be hard to see)."""
    rng = f.rng
    if subtype == "low_rate":
        rate, duration = rng.uniform(30, 80), rng.uniform(20, 30)
    else:
        rate, duration = rng.uniform(200, 800), rng.uniform(8, 15)
    single = subtype == "single_source"
    t, sent = t0, 0
    while t < t0 + duration:
        src = attacker.ip if single else f.net.random_public_ip()
        sport = rng.randrange(1024, 65536)
        seq = rng.getrandbits(32)
        f.tcp(t, src, target.ip, sport, port, "S", seq=seq)
        if sent < BACKLOG or rng.random() < 0.02:
            f.tcp(t + 0.0004, target.ip, src, port, sport, "SA", seq=rng.getrandbits(32),
                  ack=seq + 1, options=MSS_ONLY)
            if single:
                # The attacker's own stack never opened this connection, so it resets it.
                f.tcp(t + 0.0008, src, target.ip, sport, port, "R", seq=seq + 1)
        sent += 1
        t += rng.expovariate(rate)
    return label("attack", "syn_flood", subtype, [attacker.ip] if single else [], [target.ip],
                 t0, t, port=port, rate=round(rate, 1), syns=sent)


def arp_mitm(f: Frames, t0: float, attacker: Host, victim: Host, gateway: Host) -> dict:
    """Poison both ends: tell the victim the gateway is at the attacker's MAC, and
    the gateway that the victim is. Repeated so the entries don't heal."""
    rng = f.rng
    duration, gap = rng.uniform(30, 45), rng.uniform(1.0, 3.0)
    t = t0
    while t < t0 + duration:
        f.arp_reply(t, attacker.mac, gateway.ip, victim.mac_at(t), victim.ip)
        f.arp_reply(t + 0.001, attacker.mac, victim.ip, gateway.mac, gateway.ip)
        t += rng.uniform(0.7 * gap, 1.3 * gap)
    return label("attack", "arp_spoof", "mitm", [attacker.ip], [gateway.ip, victim.ip], t0, t,
                 attacker_mac=attacker.mac, gap=round(gap, 2))


def arp_announce(f: Frames, t0: float, attacker: Host, victim: Host, subtype: str) -> dict:
    """Broadcast replies claiming the victim's address. subtype 'gratuitous' targets
    a busy server; 'quiet_host' targets a host that rarely sends anything."""
    rng = f.rng
    count, low, high = (rng.randint(2, 4), 8, 15) if subtype == "quiet_host" else (rng.randint(3, 6), 5, 12)
    t = t0
    for i in range(count):
        if i:
            t += rng.uniform(low, high)
        f.arp_reply(t, attacker.mac, victim.ip, BROADCAST, victim.ip)
    return label("attack", "arp_spoof", subtype, [attacker.ip], [victim.ip], t0, t,
                 attacker_mac=attacker.mac, announcements=count)
