"""Per-host summaries of recent traffic: connection attempts in sliding windows,
handshake progress, and the IP-to-MAC table."""

from collections import deque


class ConnectionAttempt:
    """One SYN, shared by the source's scan window and the service's flood window."""

    # Incomplete means "no completion observed yet", not "will fail".
    # Each SYN counts as an attempt, including retransmissions. Sharing this object
    # lets a later ACK update both views without re-reading the capture.

    def __init__(self, timestamp: float, source_ip: str, destination_ip: str, destination_port: int):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.syn_ack_seen = False
        self.handshake_complete = False
        self.in_scan_window = False
        self.in_flood_window = False
        self.previous_attempt = None  # An earlier SYN for the same connection.


class SourceWindow:
    """Attempts from one source, including distinct targets still incomplete."""

    # Scan breadth is the number of dictionary keys, each an
    # (IP, port) pair. Values count outstanding attempts to that pair. Ten SYNs to
    # the same port on the same host increase the value, but add only one key.

    def __init__(self):
        self.attempts = deque()
        self.incomplete_targets = {}

    def add(self, connection: ConnectionAttempt) -> None:
        self.attempts.append(connection)
        connection.in_scan_window = True
        key = (connection.destination_ip, connection.destination_port)
        self.incomplete_targets[key] = self.incomplete_targets.get(key, 0) + 1

    def expire(self, cutoff: float) -> None:
        # A sliding window drops attempts older than now - window.
        # The deque is ordered by capture time, so the oldest entry is at the left.
        # An entry exactly at the cutoff stays until the next time advance.
        # This assumes chronological input; mock/generate.py sorts its packets.
        attempts = self.attempts
        while attempts and attempts[0].timestamp < cutoff:
            connection = attempts.popleft()
            connection.in_scan_window = False
            if not connection.handshake_complete:
                self.remove_incomplete_attempt(connection)

    def remove_incomplete_attempt(self, connection: ConnectionAttempt) -> None:
        # Called when an attempt completes or ages out. Remove the target key
        # only after its last incomplete attempt leaves, preserving distinctness.
        key = (connection.destination_ip, connection.destination_port)
        remaining_attempts = self.incomplete_targets[key] - 1
        if remaining_attempts:
            self.incomplete_targets[key] = remaining_attempts
        else:
            del self.incomplete_targets[key]


class ServiceWindow:
    """SYNs received by one (host, port) and how many of them completed."""

    # Flood detection combines all sources arriving at this service.
    # len(attempts) - completed_count is the number still incomplete in the window.
    # Grouping by port keeps a scan spread across ports from looking like one flood.

    def __init__(self):
        self.attempts = deque()
        self.completed_count = 0

    def add(self, connection: ConnectionAttempt) -> None:
        self.attempts.append(connection)
        connection.in_flood_window = True

    def expire(self, cutoff: float) -> None:
        attempts = self.attempts
        while attempts and attempts[0].timestamp < cutoff:
            connection = attempts.popleft()
            connection.in_flood_window = False
            if connection.handshake_complete:
                self.completed_count -= 1


class ArpBinding:
    # "trusted" starts as the first observed MAC, not an authenticated
    # owner. "mac" is the latest claim; "contender" remembers a competing claimant.
    # rules.arp_spoof() uses those roles to recognize claims switching back and forth.
    def __init__(self, mac: str, now: float):
        self.mac = mac          # most recent claim
        self.trusted = mac      # long-standing owner
        self.contender = None   # last other MAC that claimed this IP
        self.since = now
        self.changed_at = now


class State:
    def __init__(self, scan_window: float, flood_window: float, connection_timeout: float = 60.0):
        self.scan_window = scan_window
        self.flood_window = flood_window
        self.connection_timeout = connection_timeout
        # Look up a handshake by (client IP, client port, server IP, server port).
        self.pending_connections: dict[tuple, ConnectionAttempt] = {}
        self.sources: dict[str, SourceWindow] = {}
        self.services: dict[tuple, ServiceWindow] = {}
        self.bindings: dict[str, ArpBinding] = {}
        self.mac_seen: dict[str, float] = {}            # last frame sent by each MAC
        self.mac_owner: dict[str, str] = {}             # first IP each MAC announced

    def record_syn(self, packet) -> tuple[SourceWindow, ServiceWindow]:
        """Record an attempt in both traffic windows, then return those windows."""
        # The four values distinguish simultaneous connections to
        # the same server. Retries with the same tuple are linked so a successful
        # handshake can mark the linked outstanding SYN attempts complete together.
        key = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port)
        connection = ConnectionAttempt(packet.timestamp, packet.source_ip, packet.destination_ip,
            packet.destination_port)
        earlier = self.pending_connections.get(key)
        if earlier is not None and packet.timestamp - earlier.timestamp <= self.connection_timeout:
            connection.previous_attempt = earlier
        self.pending_connections[key] = connection

        source = self.sources.get(packet.source_ip)
        if source is None:
            source = SourceWindow()
            self.sources[packet.source_ip] = source
        # Expire before adding/checking: an old attempt must not inflate this rule.
        source.expire(packet.timestamp - self.scan_window)
        source.add(connection)

        service_key = (packet.destination_ip, packet.destination_port)
        service = self.services.get(service_key)
        if service is None:
            service = ServiceWindow()
            self.services[service_key] = service
        service.expire(packet.timestamp - self.flood_window)
        service.add(connection)
        return source, service

    def record_syn_ack(self, packet) -> None:
        # The server reply travels in the opposite direction to the first SYN.
        key = (packet.destination_ip, packet.destination_port, packet.source_ip, packet.source_port)
        connection = self.pending_connections.get(key)
        if connection is not None:
            connection.syn_ack_seen = True

    def record_ack(self, packet) -> None:
        """The client's ACK after a SYN-ACK completes the handshake."""
        # An arbitrary ACK is insufficient; a matching SYN and
        # SYN-ACK must already have been seen. This is simplified tracking: it
        # checks direction/flags, not TCP sequence or acknowledgment numbers.
        # If the capture misses replies, legitimate connections can look incomplete.
        key = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port)
        connection = self.pending_connections.get(key)
        if connection is None or not connection.syn_ack_seen:
            return
        del self.pending_connections[key]
        while connection is not None:
            # Scan and flood windows can have different lengths. Only adjust a
            # counter if this attempt is still in that window; otherwise its
            # contribution has already expired. The loop then follows retry links.
            if not connection.handshake_complete:
                connection.handshake_complete = True
                if connection.in_scan_window:
                    self.sources[connection.source_ip].remove_incomplete_attempt(connection)
                if connection.in_flood_window:
                    service_key = (connection.destination_ip, connection.destination_port)
                    self.services[service_key].completed_count += 1
            previous_attempt = connection.previous_attempt
            connection.previous_attempt = None
            connection = previous_attempt

    def record_reset(self, packet) -> None:
        # A refused connection is still incomplete for the scan and flood rules.
        forward = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port)
        reverse = (packet.destination_ip, packet.destination_port, packet.source_ip, packet.source_port)
        self.pending_connections.pop(forward, None)
        self.pending_connections.pop(reverse, None)

    def prune(self, now: float) -> None:
        """Drop idle entries so spoofed sources don't accumulate."""
        # Cleanup bounds the stored history; it does not classify traffic.
        # Pending-handshake timeout and detection-window length are separate:
        # forgetting a handshake does not remove still-recent incomplete evidence.
        cutoff = now - self.connection_timeout
        for key in list(self.pending_connections):
            connection = self.pending_connections[key]
            if connection.timestamp < cutoff:
                del self.pending_connections[key]
        for table, window in ((self.sources, self.scan_window), (self.services, self.flood_window)):
            for key in list(table):
                entry = table[key]
                entry.expire(now - window)
                if not entry.attempts:
                    del table[key]
