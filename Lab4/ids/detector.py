"""For each packet: update traffic history, check rules, return new alerts."""

from . import rules
from .alerts import RANK, Alert, AlertLog
from .packets import ACK, ARP_KIND, RST, SYN, TCP_KIND, PacketInfo, decode
from .rules import ARP_SPOOF, PORT_SCAN, RULES, SYN_FLOOD, Config
from .state import State

CLEANUP_INTERVAL = 10.0


class Detector:
    def __init__(self, config: Config | None = None, enabled_rules=RULES):
        # One Detector persists across the capture, so packets share history.
        # State remembers traffic; rules decide; AlertLog stores the findings.
        self.config = config or Config()
        self.enabled_rules = enabled_rules  # Evaluation can tune one rule at a time.
        self.log = AlertLog()
        self.state = State(self.config.port_scan.window, self.config.syn_flood.window)
        self.current_time = 0.0
        self.peak: dict[str, str] = {}  # Highest severity ever seen for each host.
        self.next_cleanup = None

    @property
    def alerts(self) -> list[Alert]:
        return self.log.alerts

    def handle(self, captured_packet) -> list[Alert]:
        """Extract Scapy's header fields, then process the resulting packet record."""
        # run.py supplies a Scapy packet. decode(), in
        # ids/packets.py, keeps only the fields our own rules need.
        packet = decode(captured_packet)
        return self.handle_info(packet)

    def handle_info(self, packet: PacketInfo) -> list[Alert]:
        """Update history and return any alerts created by this packet."""
        # Use capture time so window lengths are independent of replay speed.
        # Reading a seven-minute capture quickly still gives seven-minute windows.
        # evaluate.py calls this directly to reuse packets already decoded once.
        self.current_time = packet.timestamp
        previous_alert_count = len(self.alerts)

        if packet.source_mac is not None:
            # Any observed frame can show that the previous MAC is still active.
            # arp_spoof() uses this to distinguish an address conflict from silence.
            self.state.mac_seen[packet.source_mac] = packet.timestamp

        if packet.kind == TCP_KIND:
            if PORT_SCAN in self.enabled_rules or SYN_FLOOD in self.enabled_rules:
                self.handle_tcp_packet(packet)
        elif packet.kind == ARP_KIND and ARP_SPOOF in self.enabled_rules:
            # ARP is a separate protocol; its rule does not use TCP handshakes.
            rules.arp_spoof(self.config.arp_spoof, self.log, self.state, packet)

        # Periodically discard old connections and empty traffic summaries.
        if self.next_cleanup is None:
            self.next_cleanup = packet.timestamp + CLEANUP_INTERVAL
        elif packet.timestamp >= self.next_cleanup:
            self.state.prune(packet.timestamp)
            self.next_cleanup = packet.timestamp + CLEANUP_INTERVAL

        new_alerts = self.alerts[previous_alert_count:]
        # Keep the historical peak, then return only newly created records to
        # run.py for printing. Refreshing a record does not print another finding.
        for alert in new_alerts:
            for host in (alert.actor, alert.target):
                if host is None:
                    continue
                previous_severity = self.peak.get(host, "ok")
                if RANK[alert.severity] > RANK[previous_severity]:
                    self.peak[host] = alert.severity
        return new_alerts

    def handle_tcp_packet(self, packet: PacketInfo) -> None:
        # TCP setup is client SYN -> server SYN-ACK -> client ACK.
        # This selects a state update; the attack thresholds live in rules.py.
        # A packet can carry several flags; '&' checks one flag's bit.
        has_syn = bool(packet.flags & SYN)
        has_ack = bool(packet.flags & ACK)
        has_reset = bool(packet.flags & RST)

        if has_syn and has_ack:
            # Check this first: a SYN-ACK also contains SYN, but is a reply.
            # Counting it as another initial attempt would inflate traffic volume.
            self.state.record_syn_ack(packet)
        elif has_syn:
            # State.record_syn() updates two views of this same attempt:
            # source_window = where one source connects (scan breadth);
            # service_window = attempts arriving at one IP/port (flood volume).
            source_window, service_window = self.state.record_syn(packet)
            # These checks mean "rule enabled", not "attack detected".
            # Separate if statements allow both rules to fire for the same host.
            # Each rule evaluates its own evidence independently.
            if PORT_SCAN in self.enabled_rules:
                rules.port_scan(self.config.port_scan, self.log, packet.timestamp,
                                packet.source_ip, source_window)
            if SYN_FLOOD in self.enabled_rules:
                rules.syn_flood(self.config.syn_flood, self.log, packet.timestamp,
                                packet.destination_ip, packet.destination_port, service_window)
        elif has_reset:
            # RST refuses/resets the connection; it is not a completed handshake.
            self.state.record_reset(packet)
        elif has_ack:
            # Completion updates the counts used on the next initial SYN.
            # Existing alert history is retained even if a connection later succeeds.
            self.state.record_ack(packet)

    def host_status(self, now: float | None = None) -> dict[str, dict]:
        """A host's status is the highest severity among its active alerts."""
        # Keep all active findings, but display their maximum severity.
        # A host can be listed as actor, target, or both across different findings.
        # Expiry controls display retention, not proof that the attack has ended.
        if now is None:
            now = self.current_time
        status = {}
        for address in self.state.bindings:
            status[address] = {"status": "ok", "alerts": []}

        for alert in self.log.active(now):
            for role, host in (("actor", alert.actor), ("target", alert.target)):
                if host is None:
                    continue
                if host not in status:
                    status[host] = {"status": "ok", "alerts": []}
                entry = status[host]
                entry["alerts"].append({"id": alert.id, "rule": alert.rule, "role": role,
                                        "severity": alert.severity})
                if RANK[alert.severity] > RANK[entry["status"]]:
                    entry["status"] = alert.severity
        return status
