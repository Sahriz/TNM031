"""Attack traffic. Every function adds frames and returns the label for what it added."""

from .frames import BROADCAST, MSS_ONLY, Frames
from .hosts import SWEEP_SUBNET, Host

BACKLOG = 256  # SYNs a flooded server still answers before its queue is full


def label(kind: str, rule: str, subtype: str, actors: list, targets: list,
          start: float, end: float, **parameters) -> dict:
    # Labels describe known generated events, not detector predictions.
    # evaluate.match() compares rule, relevant host and onset against these times.
    return {"kind": kind, "rule": rule, "subtype": subtype, "actors": actors, "targets": targets,
            "start": round(start, 6), "end": round(end, 6), "params": parameters}


def _probe(frame_builder: Frames, timestamp: float, source_ip: str, destination_ip: str, port: int,
    answer: str) -> None:
    """One SYN scan probe. answer: 'open' (SYN-ACK, then the scanner resets),
    'closed' (RST) or 'filtered' (nothing)."""
    source_port = frame_builder.random_generator.randrange(32768, 61000)
    sequence_number = frame_builder.random_generator.getrandbits(32)
    frame_builder.tcp(timestamp, source_ip, destination_ip, source_port, port, "S",
        sequence_number=sequence_number, options=MSS_ONLY)
    if answer == "filtered":
        return
    reply_at = timestamp + frame_builder.round_trip_time(source_ip, destination_ip)
    if answer == "open":
        frame_builder.tcp(reply_at, destination_ip, source_ip, port, source_port, "SA",
            sequence_number=frame_builder.random_generator.getrandbits(32),
            acknowledgment_number=sequence_number + 1, options=MSS_ONLY)
        frame_builder.tcp(reply_at + 0.0003, source_ip, destination_ip, source_port, port, "R",
            sequence_number=sequence_number + 1)
    else:
        frame_builder.tcp(reply_at, destination_ip, source_ip, port, source_port, "RA",
            acknowledgment_number=sequence_number + 1)


def _answer(frame_builder: Frames, target: Host, port: int, filtered: float) -> str:
    if port in target.open_ports:
        return "open"
    return "filtered" if frame_builder.random_generator.random() < filtered else "closed"


def vertical_scan(frame_builder: Frames, start_time: float, attacker: Host, target: Host) -> dict:
    """Many ports on one host, fast."""
    # Same source and destination, many ports: this grows SourceWindow's distinct
    # (IP, port) keys. Open-port probes reset instead of completing the handshake.
    random_generator = frame_builder.random_generator
    count, rate, filtered = random_generator.randint(100, 1000), random_generator.uniform(50,
        400), random_generator.uniform(0, 0.3)
    ports = set(random_generator.sample(range(1, 10001), count)) | set(target.open_ports)
    timestamp = start_time
    for port in random_generator.sample(sorted(ports), len(ports)):
        _probe(frame_builder, timestamp, attacker.ip, target.ip, port, _answer(frame_builder, target, port, filtered))
        timestamp += random_generator.expovariate(rate)
    return label("attack", "port_scan", "vertical", [attacker.ip], [target.ip], start_time, timestamp,
                 ports=len(ports), rate=round(rate, 1))


def slow_scan(frame_builder: Frames, start_time: float, end_time: float, attacker: Host, target: Host) -> dict:
    """A few seconds between probes, to stay under rate thresholds."""
    # Spacing probes out can let older attempts expire before the
    # count reaches the threshold. The selected window may still catch larger cases.
    random_generator = frame_builder.random_generator
    gap = random_generator.uniform(1.5, 5.0)
    count = min(random_generator.randint(40, 90), int((end_time - start_time - 5) / gap))
    timestamp = start_time
    for port in random_generator.sample(range(1, 10001), count):
        _probe(frame_builder, timestamp, attacker.ip, target.ip, port, _answer(frame_builder, target, port, 0.1))
        timestamp += random_generator.uniform(0.5 * gap, 1.5 * gap)
    return label("attack", "port_scan", "slow", [attacker.ip], [target.ip], start_time, timestamp,
                 ports=count, mean_gap=round(gap, 2))


def sweep_scan(frame_builder: Frames, start_time: float, attacker: Host) -> dict:
    """One or two ports across a whole subnet."""
    # Many destination IPs, few ports: each distinct IP/port still contributes one
    # scan target. rules._scan_evidence() calls this breadth pattern a portsweep.
    random_generator = frame_builder.random_generator
    ports = random_generator.choice(([445], [22], [3389], [22, 3389]))
    rate = random_generator.uniform(40, 200)
    alive = set(random_generator.sample(range(1, 255), 25))
    timestamp = start_time
    for host_number in random_generator.sample(range(1, 255), 254):
        for port in ports:
            answer = random_generator.choice(("open", "closed")) if host_number in alive else "filtered"
            _probe(frame_builder, timestamp, attacker.ip, f"{SWEEP_SUBNET}{host_number}", port, answer)
            timestamp += random_generator.expovariate(rate)
    return label("attack", "port_scan", "sweep", [attacker.ip], [f"{SWEEP_SUBNET}0/24"], start_time, timestamp,
                 ports=ports, rate=round(rate, 1))


def distributed_scan(frame_builder: Frames, start_time: float, target: Host) -> dict:
    """Many sources, each probing only a handful of ports on the same host."""
    # Scan counters are per source, so these small contributions are not combined.
    # The total scan can be large while each source stays below the threshold.
    random_generator = frame_builder.random_generator
    sources = [frame_builder.network.random_public_ip() for _ in range(random_generator.randint(8, 15))]
    rate = random_generator.uniform(5, 30)
    probes = [(source_ip, port) for source_ip in sources
              for port in random_generator.sample(range(1, 10001), random_generator.randint(5, 12))]
    random_generator.shuffle(probes)
    timestamp = start_time
    for source_ip, port in probes:
        _probe(frame_builder, timestamp, source_ip, target.ip, port, _answer(frame_builder, target, port, 0.1))
        timestamp += random_generator.expovariate(rate)
    return label("attack", "port_scan", "distributed", sources, [target.ip], start_time, timestamp,
                 sources=len(sources), probes=len(probes), rate=round(rate, 1))


def syn_flood(frame_builder: Frames, start_time: float, target: Host, port: int, subtype: str,
              attacker: Host | None = None) -> dict:
    """subtype: 'single_source' (attacker's own address), 'spoofed' (random
    source addresses) or 'low_rate' (spoofed, slow enough to be hard to see)."""
    random_generator = frame_builder.random_generator
    if subtype == "low_rate":
        rate, duration = random_generator.uniform(30, 80), random_generator.uniform(20, 30)
    else:
        rate, duration = random_generator.uniform(200, 800), random_generator.uniform(8, 15)
    single = subtype == "single_source"
    timestamp, sent = start_time, 0
    while timestamp < start_time + duration:
        source_ip = attacker.ip if single else frame_builder.network.random_public_ip()
        source_port = random_generator.randrange(1024, 65536)
        sequence_number = random_generator.getrandbits(32)
        frame_builder.tcp(timestamp, source_ip, target.ip, source_port, port, "S", sequence_number=sequence_number)
        if sent < BACKLOG or random_generator.random() < 0.02:
            frame_builder.tcp(timestamp + 0.0004, target.ip, source_ip, port, source_port, "SA",
                sequence_number=random_generator.getrandbits(32),
                  acknowledgment_number=sequence_number + 1, options=MSS_ONLY)
            if single:
                # The attacker's own stack never opened this connection, so it resets it.
                frame_builder.tcp(timestamp + 0.0008, source_ip, target.ip, source_port, port, "R",
                    sequence_number=sequence_number + 1)
        sent += 1
        timestamp += random_generator.expovariate(rate)
    return label("attack", "syn_flood", subtype, [attacker.ip] if single else [], [target.ip],
                 start_time, timestamp, port=port, rate=round(rate, 1), syns=sent)


def arp_mitm(frame_builder: Frames, start_time: float, attacker: Host, victim: Host, gateway: Host) -> dict:
    """Poison both ends: tell the victim the gateway is at the attacker's MAC, and
    the gateway that the victim is. Repeated so the entries don't heal."""
    random_generator = frame_builder.random_generator
    duration, gap = random_generator.uniform(30, 45), random_generator.uniform(1.0, 3.0)
    timestamp = start_time
    while timestamp < start_time + duration:
        frame_builder.arp_reply(timestamp, attacker.mac, gateway.ip, victim.mac_at(timestamp), victim.ip)
        frame_builder.arp_reply(timestamp + 0.001, attacker.mac, victim.ip, gateway.mac, gateway.ip)
        timestamp += random_generator.uniform(0.7 * gap, 1.3 * gap)
    return label("attack", "arp_spoof", "mitm", [attacker.ip], [gateway.ip, victim.ip], start_time, timestamp,
                 attacker_mac=attacker.mac, gap=round(gap, 2))


def arp_announce(frame_builder: Frames, start_time: float, attacker: Host, victim: Host, subtype: str) -> dict:
    """Broadcast replies claiming the victim's address. subtype 'gratuitous' targets
    a busy server; 'quiet_host' targets a host that rarely sends anything."""
    # A quiet victim can make a malicious address change look like replaced
    # hardware. The ARP rule may report only low severity; scoring excludes those
    # alerts, so an attack with only low-severity findings counts as missed.
    random_generator = frame_builder.random_generator
    count, low, high = (random_generator.randint(2, 4), 8,
        15) if subtype == "quiet_host" else (random_generator.randint(3, 6), 5, 12)
    timestamp = start_time
    for index in range(count):
        if index:
            timestamp += random_generator.uniform(low, high)
        frame_builder.arp_reply(timestamp, attacker.mac, victim.ip, BROADCAST, victim.ip)
    return label("attack", "arp_spoof", subtype, [attacker.ip], [victim.ip], start_time, timestamp,
                 attacker_mac=attacker.mac, announcements=count)
