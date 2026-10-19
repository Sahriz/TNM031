"""The simulated LAN: a gateway, three servers, a printer and a set of clients."""

import zlib
from dataclasses import dataclass, field

BASE_TIME = 1_790_000_000.0  # late September 2026
SWEEP_SUBNET = "10.0.1."     # second internal subnet, reached through the gateway

_OUIS = ("3c:52:82", "f4:5c:89", "00:1b:21", "b8:27:eb", "a4:bb:6d", "d8:bb:c1")


@dataclass
class Host:
    name: str
    ip: str
    mac: str
    ttl: int = 64
    open_ports: frozenset = frozenset()
    offline: tuple[float, float] | None = None  # set by the NIC replacement look-alike
    new_mac: str | None = None

    def mac_at(self, timestamp: float) -> str:
        if self.offline is not None and timestamp >= self.offline[1]:
            return self.new_mac
        return self.mac

    def online(self, timestamp: float) -> bool:
        return self.offline is None or not (self.offline[0] <= timestamp < self.offline[1])


@dataclass
class Network:
    random_generator: object
    hosts: dict[str, Host] = field(default_factory=dict)

    def __post_init__(self):
        random_generator = self.random_generator
        self.gateway = self._add("gateway", "10.0.0.1")
        self.web = self._add("web", "10.0.0.10", open_ports=frozenset({80, 443}))
        self.dns = self._add("dns", "10.0.0.11", open_ports=frozenset({53}))
        self.files = self._add("files", "10.0.0.12", open_ports=frozenset({9000}))
        self.printer = self._add("printer", "10.0.0.50", open_ports=frozenset({9100}))
        self.clients = [self._add(f"client{index:02d}", f"10.0.0.{100 + index}", ttl=random_generator.choice((64, 128)))
                        for index in range(13)]
        self.external_web = [f"203.0.113.{host_number}" for host_number in random_generator.sample(range(2, 250), 20)]
        self._ip_id: dict[str, int] = {}
        self._port: dict[str, int] = {}

    def _add(self, name: str, ip: str, **kwargs) -> Host:
        host = Host(name, ip, self.random_mac(), **kwargs)
        self.hosts[ip] = host
        return host

    def random_mac(self) -> str:
        tail = ":".join(f"{self.random_generator.randrange(256):02x}" for _ in range(3))
        return f"{self.random_generator.choice(_OUIS)}:{tail}"

    def random_public_ip(self) -> str:
        random_generator = self.random_generator
        return f"{random_generator.choice((23, 45, 62, 81, 94, 133, 151, 176, 188, 212))}." \
               f"{random_generator.randrange(256)}.{random_generator.randrange(256)}.{random_generator.randrange(1, 255)}"

    def is_local(self, ip: str) -> bool:
        return ip in self.hosts

    def mac_for(self, ip: str, timestamp: float) -> str:
        """Frames to or from anything off the subnet carry the gateway's MAC."""
        host = self.hosts.get(ip)
        return host.mac_at(timestamp) if host is not None else self.gateway.mac

    def ttl_for(self, ip: str) -> int:
        host = self.hosts.get(ip)
        return host.ttl if host is not None else 40 + zlib.crc32(ip.encode()) % 20

    def next_ip_id(self, ip: str) -> int:
        value = self._ip_id.get(ip)
        value = self.random_generator.randrange(65536) if value is None else (value + 1) & 0xFFFF
        self._ip_id[ip] = value
        return value

    def next_port(self, ip: str) -> int:
        value = self._port.get(ip)
        value = self.random_generator.randrange(49152, 60000) if value is None else value + 1
        if value > 65535:
            value = 49152
        self._port[ip] = value
        return value
