"""Per-host summaries of recent traffic: connection attempts in sliding windows,
handshake progress, and the IP-to-MAC table."""

from collections import deque


class Conn:
    """One SYN. Lives in its source's and its service's window until it expires."""

    __slots__ = ("ts", "src", "dst", "dport", "synack", "established", "in_scan", "in_flood", "prev")

    def __init__(self, ts: float, src: str, dst: str, dport: int):
        self.ts = ts
        self.src = src
        self.dst = dst
        self.dport = dport
        self.synack = False
        self.established = False
        self.in_scan = False
        self.in_flood = False
        self.prev = None  # earlier SYN of the same 4-tuple (retransmission)


class SourceWindow:
    """Connection attempts made by one source. `failed` maps each (host, port) the
    source has an uncompleted attempt to, so len(failed) is the scan measure."""

    __slots__ = ("attempts", "failed")

    def __init__(self):
        self.attempts = deque()
        self.failed = {}

    def add(self, conn: Conn) -> None:
        self.attempts.append(conn)
        conn.in_scan = True
        key = (conn.dst, conn.dport)
        self.failed[key] = self.failed.get(key, 0) + 1

    def expire(self, cutoff: float) -> None:
        attempts = self.attempts
        while attempts and attempts[0].ts < cutoff:
            conn = attempts.popleft()
            conn.in_scan = False
            if not conn.established:
                self.completed(conn)

    def completed(self, conn: Conn) -> None:
        key = (conn.dst, conn.dport)
        left = self.failed[key] - 1
        if left:
            self.failed[key] = left
        else:
            del self.failed[key]


class ServiceWindow:
    """SYNs received by one (host, port) and how many of them completed."""

    __slots__ = ("attempts", "completed")

    def __init__(self):
        self.attempts = deque()
        self.completed = 0

    def add(self, conn: Conn) -> None:
        self.attempts.append(conn)
        conn.in_flood = True

    def expire(self, cutoff: float) -> None:
        attempts = self.attempts
        while attempts and attempts[0].ts < cutoff:
            conn = attempts.popleft()
            conn.in_flood = False
            if conn.established:
                self.completed -= 1


class ArpBinding:
    __slots__ = ("mac", "trusted", "contender", "since", "changed_at")

    def __init__(self, mac: str, now: float):
        self.mac = mac          # most recent claim
        self.trusted = mac      # long-standing owner
        self.contender = None   # last other MAC that claimed this IP
        self.since = now
        self.changed_at = now


class State:
    def __init__(self, scan_window: float, flood_window: float, conn_timeout: float = 60.0):
        self.scan_window = scan_window
        self.flood_window = flood_window
        self.conn_timeout = conn_timeout
        self.conns: dict[tuple, Conn] = {}              # pending handshakes by (client, cport, server, sport)
        self.sources: dict[str, SourceWindow] = {}
        self.services: dict[tuple, ServiceWindow] = {}
        self.bindings: dict[str, ArpBinding] = {}
        self.mac_seen: dict[str, float] = {}            # last frame sent by each MAC
        self.mac_owner: dict[str, str] = {}             # first IP each MAC announced

    def syn(self, p) -> tuple[SourceWindow, ServiceWindow]:
        key = (p.src_ip, p.sport, p.dst_ip, p.dport)
        conn = Conn(p.ts, p.src_ip, p.dst_ip, p.dport)
        earlier = self.conns.get(key)
        if earlier is not None and p.ts - earlier.ts <= self.conn_timeout:
            conn.prev = earlier
        self.conns[key] = conn

        source = self.sources.get(p.src_ip)
        if source is None:
            source = self.sources[p.src_ip] = SourceWindow()
        source.expire(p.ts - self.scan_window)
        source.add(conn)

        service_key = (p.dst_ip, p.dport)
        service = self.services.get(service_key)
        if service is None:
            service = self.services[service_key] = ServiceWindow()
        service.expire(p.ts - self.flood_window)
        service.add(conn)
        return source, service

    def synack(self, p) -> None:
        conn = self.conns.get((p.dst_ip, p.dport, p.src_ip, p.sport))
        if conn is not None:
            conn.synack = True

    def ack(self, p) -> None:
        """The client's ACK after a SYN-ACK completes the handshake."""
        key = (p.src_ip, p.sport, p.dst_ip, p.dport)
        conn = self.conns.get(key)
        if conn is None or not conn.synack:
            return
        del self.conns[key]
        while conn is not None:
            if not conn.established:
                conn.established = True
                if conn.in_scan:
                    self.sources[conn.src].completed(conn)
                if conn.in_flood:
                    self.services[(conn.dst, conn.dport)].completed += 1
            conn.prev, conn = None, conn.prev

    def rst(self, p) -> None:
        self.conns.pop((p.src_ip, p.sport, p.dst_ip, p.dport), None)
        self.conns.pop((p.dst_ip, p.dport, p.src_ip, p.sport), None)

    def prune(self, now: float) -> None:
        """Drop idle entries so spoofed sources don't accumulate."""
        cutoff = now - self.conn_timeout
        for key in [k for k, c in self.conns.items() if c.ts < cutoff]:
            del self.conns[key]
        for table, window in ((self.sources, self.scan_window), (self.services, self.flood_window)):
            for key in list(table):
                entry = table[key]
                entry.expire(now - window)
                if not entry.attempts:
                    del table[key]
