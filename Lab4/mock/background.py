"""Normal traffic: clients browsing, DNS lookups, ARP refreshes, the odd failed connection."""

from .frames import Frames, http_request, http_response, tls_record, tls_records

DOMAINS = [f"{name}.example" for name in (
    "www.shop", "cdn.shop", "mail", "news", "api.weather", "static.news", "video", "img.video",
    "docs", "login", "search", "maps", "music", "updates", "cloud", "sync.cloud", "chat",
    "forum", "wiki", "status")]
CLOSED_PORTS = (21, 23, 3306, 8080, 8443)
MEAN_GAP = 8.0  # seconds between one client's activities


def background(frame_builder: Frames, start: float, end: float) -> None:
    network, random_generator = frame_builder.network, frame_builder.random_generator
    names = list(zip(DOMAINS, network.external_web))

    for host in network.hosts.values():
        if host is network.gateway:
            continue
        low, high = (200.0, 400.0) if host is network.printer else (30.0, 90.0)
        timestamp = start + random_generator.uniform(0.05, 3.0)
        while timestamp < end:
            if host.online(timestamp):
                if random_generator.random() < 0.7:
                    frame_builder.arp_exchange(timestamp, host, network.gateway)
                else:
                    frame_builder.arp_exchange(timestamp, network.gateway, host)
            timestamp += random_generator.uniform(low, high)

    for client in network.clients:
        timestamp = start + 3.0 + random_generator.expovariate(1 / MEAN_GAP)
        while timestamp < end:
            if client.online(timestamp) and client.online(timestamp + 2.0):
                _activity(frame_builder, timestamp, client.ip, names)
            timestamp += random_generator.expovariate(1 / MEAN_GAP)


def _activity(frame_builder: Frames, timestamp: float, client: str, names: list) -> None:
    network, random_generator = frame_builder.network, frame_builder.random_generator
    roll = random_generator.random()
    if roll < 0.55:
        name, ip = random_generator.choice(names)
        timestamp = frame_builder.dns(timestamp, client, network.dns.ip, name, ip)
        frame_builder.session(timestamp + random_generator.uniform(0.001, 0.02), client, ip, 443,
                  tls_record(random_generator, random_generator.randrange(200, 600)),
                      tls_records(random_generator, random_generator.randint(1, 4)))
    elif roll < 0.68:
        frame_builder.session(timestamp, client, network.web.ip, 80, http_request("web.lan",
            f"/page{random_generator.randrange(50)}"),
                  http_response(random_generator, random_generator.randrange(200, 4000)))
    elif roll < 0.80:
        frame_builder.session(timestamp, client, network.web.ip, 443,
                  tls_record(random_generator, random_generator.randrange(200, 600)),
                      tls_records(random_generator, random_generator.randint(1, 3)))
    elif roll < 0.90:
        frame_builder.session(timestamp, client, network.files.ip, 9000,
                  random_generator.randbytes(random_generator.randrange(40, 200)),
                      [random_generator.randbytes(random_generator.randrange(100, 1400))])
    elif roll < 0.95:
        name, ip = random_generator.choice(names)
        frame_builder.dns(timestamp, client, network.dns.ip, name, ip)
    elif roll < 0.98:
        server = random_generator.choice((network.web, network.files, network.dns))
        frame_builder.refused(timestamp, client, server.ip, random_generator.choice(CLOSED_PORTS))
    else:
        frame_builder.unanswered(timestamp, client, random_generator.choice(network.external_web), 443)
