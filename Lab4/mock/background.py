"""Normal traffic: clients browsing, DNS lookups, ARP refreshes, the odd failed connection."""

from .frames import Frames, http_request, http_response, tls_record, tls_records

DOMAINS = [f"{name}.example" for name in (
    "www.shop", "cdn.shop", "mail", "news", "api.weather", "static.news", "video", "img.video",
    "docs", "login", "search", "maps", "music", "updates", "cloud", "sync.cloud", "chat",
    "forum", "wiki", "status")]
CLOSED_PORTS = (21, 23, 3306, 8080, 8443)
MEAN_GAP = 8.0  # seconds between one client's activities


def background(f: Frames, start: float, end: float) -> None:
    net, rng = f.net, f.rng
    names = list(zip(DOMAINS, net.external_web))

    for host in net.hosts.values():
        if host is net.gateway:
            continue
        low, high = (200.0, 400.0) if host is net.printer else (30.0, 90.0)
        t = start + rng.uniform(0.05, 3.0)
        while t < end:
            if host.online(t):
                if rng.random() < 0.7:
                    f.arp_exchange(t, host, net.gateway)
                else:
                    f.arp_exchange(t, net.gateway, host)
            t += rng.uniform(low, high)

    for client in net.clients:
        t = start + 3.0 + rng.expovariate(1 / MEAN_GAP)
        while t < end:
            if client.online(t) and client.online(t + 2.0):
                _activity(f, t, client.ip, names)
            t += rng.expovariate(1 / MEAN_GAP)


def _activity(f: Frames, t: float, client: str, names: list) -> None:
    net, rng = f.net, f.rng
    roll = rng.random()
    if roll < 0.55:
        name, ip = rng.choice(names)
        t = f.dns(t, client, net.dns.ip, name, ip)
        f.session(t + rng.uniform(0.001, 0.02), client, ip, 443,
                  tls_record(rng, rng.randrange(200, 600)), tls_records(rng, rng.randint(1, 4)))
    elif roll < 0.68:
        f.session(t, client, net.web.ip, 80, http_request("web.lan", f"/page{rng.randrange(50)}"),
                  http_response(rng, rng.randrange(200, 4000)))
    elif roll < 0.80:
        f.session(t, client, net.web.ip, 443,
                  tls_record(rng, rng.randrange(200, 600)), tls_records(rng, rng.randint(1, 3)))
    elif roll < 0.90:
        f.session(t, client, net.files.ip, 9000,
                  rng.randbytes(rng.randrange(40, 200)), [rng.randbytes(rng.randrange(100, 1400))])
    elif roll < 0.95:
        name, ip = rng.choice(names)
        f.dns(t, client, net.dns.ip, name, ip)
    elif roll < 0.98:
        server = rng.choice((net.web, net.files, net.dns))
        f.refused(t, client, server.ip, rng.choice(CLOSED_PORTS))
    else:
        f.unanswered(t, client, rng.choice(net.external_web), 443)
