"""Normal traffic that resembles an attack. Labeled benign, so an alert on it is a false positive."""

from .attacks import label
from .frames import Frames, tls_record
from .hosts import Host


def backup_job(f: Frames, t0: float, server: Host, client: Host) -> dict:
    """Resembles a port scan: one host connects to many ports on another, but the
    connections complete and carry data. A few ports may be closed."""
    rng = f.rng
    count, rate, fail = rng.randint(60, 200), rng.uniform(5, 20), rng.uniform(0, 0.08)
    t, failed = t0, 0
    for port in rng.sample(range(20000, 20600), count):
        if rng.random() < fail:
            f.refused(t, server.ip, client.ip, port)
            failed += 1
        else:
            f.session(t, server.ip, client.ip, port, rng.randbytes(rng.randrange(40, 200)),
                      [rng.randbytes(rng.randrange(400, 1400)) for _ in range(rng.randint(1, 3))])
        t += rng.expovariate(rate)
    return label("benign", "port_scan", "backup_job", [server.ip], [client.ip], t0, t,
                 connections=count, refused=failed, rate=round(rate, 1))


def peer_discovery(f: Frames, t0: float, client: Host) -> dict:
    """Resembles a sweep: a client tries a list of peers and many are offline."""
    rng = f.rng
    count, dead, duration = rng.randint(15, 40), rng.uniform(0.2, 0.5), rng.uniform(20, 45)
    failed = 0
    for _ in range(count):
        t = t0 + rng.uniform(0, duration)
        peer, port = f.net.random_public_ip(), rng.randrange(1024, 65536)
        if rng.random() < dead:
            failed += 1
            if rng.random() < 0.5:
                f.refused(t, client.ip, peer, port)
            else:
                f.unanswered(t, client.ip, peer, port, retries=1)
        else:
            f.session(t, client.ip, peer, port, rng.randbytes(68), [rng.randbytes(rng.randrange(100, 900))])
    return label("benign", "port_scan", "peer_discovery", [client.ip], [], t0, t0 + duration + 1,
                 peers=count, unreachable=failed)


def flash_crowd(f: Frames, t0: float, server: Host, port: int) -> dict:
    """Resembles a SYN flood: a burst of connections to one service, but they
    complete. An overloaded server drops some first SYNs, which are retried."""
    rng = f.rng
    count, duration, drop = rng.randint(150, 500), rng.uniform(3, 8), rng.uniform(0, 0.25)
    dropped = 0
    for _ in range(count):
        t = t0 + rng.uniform(0, duration)
        client, cport, isn = f.net.random_public_ip(), rng.randrange(1024, 65536), rng.getrandbits(32)
        if rng.random() < drop:
            dropped += 1
            f.unanswered(t, client, server.ip, port, retries=0, cport=cport, isn=isn)
            t += 1.0
        f.session(t, client, server.ip, port, tls_record(rng, rng.randrange(200, 500)),
                  [tls_record(rng, rng.randrange(300, 1300))], cport=cport, isn=isn)
    return label("benign", "syn_flood", "flash_crowd", [], [server.ip], t0, t0 + duration + 2,
                 port=port, connections=count, dropped=dropped)


def nic_replacement(f: Frames, t0: float, host: Host) -> dict:
    """Resembles ARP spoofing: a host goes away and comes back with a new MAC.
    Must be planned before the background is generated, which skips the host
    while it is offline."""
    rng = f.rng
    downtime = rng.uniform(15, 120)
    back = t0 + downtime
    host.offline = (t0, back)
    host.new_mac = f.net.random_mac()
    for delay in (0.0, 1.0):  # announces itself twice, as most stacks do
        f.arp_request(back + delay, host.new_mac, host.ip, host.ip)
    f.arp_exchange(back + 1.2, host, f.net.gateway)
    return label("benign", "arp_spoof", "nic_replacement", [host.ip], [host.ip], t0, back + 2,
                 downtime=round(downtime, 1), new_mac=host.new_mac)
