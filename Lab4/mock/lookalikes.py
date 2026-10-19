"""Normal traffic that resembles an attack. Labeled benign, so an alert on it is a false positive."""

# Benign traffic can resemble an attack and trigger the rules.
# A threshold detector sees behavior, not intent. evaluate.match() decides which
# resulting alerts are scored; low-severity and certain late alerts are excluded.

from .attacks import label
from .frames import Frames, tls_record
from .hosts import Host


def backup_job(frame_builder: Frames, start_time: float, server: Host, client: Host) -> dict:
    """Resembles a port scan: one host connects to many ports on another, but the
    connections complete and carry data. A few ports may be closed."""
    # Many contacted ports can be legitimate. Completed handshakes reduce the
    # scan's incomplete-target count; closed ports can still contribute evidence.
    random_generator = frame_builder.random_generator
    count, rate, fail = random_generator.randint(60, 200), random_generator.uniform(5,
        20), random_generator.uniform(0, 0.08)
    timestamp, incomplete_targets = start_time, 0
    for port in random_generator.sample(range(20000, 20600), count):
        if random_generator.random() < fail:
            frame_builder.refused(timestamp, server.ip, client.ip, port)
            incomplete_targets += 1
        else:
            frame_builder.session(timestamp, server.ip, client.ip, port,
                random_generator.randbytes(random_generator.randrange(40, 200)),
                      [random_generator.randbytes(random_generator.randrange(400,
                          1400)) for _ in range(random_generator.randint(1, 3))])
        timestamp += random_generator.expovariate(rate)
    return label("benign", "port_scan", "backup_job", [server.ip], [client.ip], start_time, timestamp,
                 connections=count, refused=incomplete_targets, rate=round(rate, 1))


def peer_discovery(frame_builder: Frames, start_time: float, client: Host) -> dict:
    """Resembles a sweep: a client tries a list of peers and many are offline."""
    # Legitimate intent with unsuccessful connections: a useful false-positive
    # challenge because incomplete attempts alone cannot establish maliciousness.
    random_generator = frame_builder.random_generator
    count, dead, duration = random_generator.randint(15, 40), random_generator.uniform(0.2,
        0.5), random_generator.uniform(20, 45)
    incomplete_targets = 0
    for _ in range(count):
        timestamp = start_time + random_generator.uniform(0, duration)
        peer, port = frame_builder.network.random_public_ip(), random_generator.randrange(1024, 65536)
        if random_generator.random() < dead:
            incomplete_targets += 1
            if random_generator.random() < 0.5:
                frame_builder.refused(timestamp, client.ip, peer, port)
            else:
                frame_builder.unanswered(timestamp, client.ip, peer, port, retries=1)
        else:
            frame_builder.session(timestamp, client.ip, peer, port, random_generator.randbytes(68),
                [random_generator.randbytes(random_generator.randrange(100, 900))])
    return label("benign", "port_scan", "peer_discovery", [client.ip], [], start_time, start_time + duration + 1,
                 peers=count, unreachable=incomplete_targets)


def flash_crowd(frame_builder: Frames, start_time: float, server: Host, port: int) -> dict:
    """Resembles a SYN flood: a burst of connections to one service, but they
    complete. An overloaded server drops some first SYNs, which are retried."""
    # Most sessions finish their handshakes even though some initial SYNs are lost.
    # High volume alone can trigger a rate threshold; completed handshakes lower
    # the incomplete ratio. tests/test_rules.py checks that distinction separately.
    random_generator = frame_builder.random_generator
    count, duration, drop = random_generator.randint(150, 500), random_generator.uniform(3,
        8), random_generator.uniform(0, 0.25)
    dropped = 0
    for _ in range(count):
        timestamp = start_time + random_generator.uniform(0, duration)
        client, client_port, initial_sequence = frame_builder.network.random_public_ip(), random_generator.randrange(1024, 65536), random_generator.getrandbits(32)
        if random_generator.random() < drop:
            dropped += 1
            frame_builder.unanswered(timestamp, client, server.ip, port, retries=0, client_port=client_port,
                initial_sequence=initial_sequence)
            timestamp += 1.0
        frame_builder.session(timestamp, client, server.ip, port, tls_record(random_generator,
            random_generator.randrange(200, 500)),
                  [tls_record(random_generator, random_generator.randrange(300, 1300))],
                      client_port=client_port, initial_sequence=initial_sequence)
    return label("benign", "syn_flood", "flash_crowd", [], [server.ip], start_time, start_time + duration + 2,
                 port=port, connections=count, dropped=dropped)


def nic_replacement(frame_builder: Frames, start_time: float, host: Host) -> dict:
    """Resembles ARP spoofing: a host goes away and comes back with a new MAC.
    Must be planned before the background is generated, which skips the host
    while it is offline."""
    # Silence followed by a new MAC is legitimate here. The ARP rule uses that
    # silence to lower severity; the same heuristic can miss a quiet-host attack.
    random_generator = frame_builder.random_generator
    downtime = random_generator.uniform(15, 120)
    back = start_time + downtime
    host.offline = (start_time, back)
    host.new_mac = frame_builder.network.random_mac()
    for delay in (0.0, 1.0):  # announces itself twice, as most stacks do
        frame_builder.arp_request(back + delay, host.new_mac, host.ip, host.ip)
    frame_builder.arp_exchange(back + 1.2, host, frame_builder.network.gateway)
    return label("benign", "arp_spoof", "nic_replacement", [host.ip], [host.ip], start_time, back + 2,
                 downtime=round(downtime, 1), new_mac=host.new_mac)
