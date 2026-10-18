"""The pipeline: one packet in, counters updated, rules checked, alerts out.
Time comes from packet timestamps, so files and live capture behave the same."""

from . import rules
from .alerts import RANK, Alert, AlertLog
from .packets import ACK, ARP_KIND, RST, SYN, TCP_KIND, PacketInfo, decode
from .rules import ARP_SPOOF, PORT_SCAN, RULES, SYN_FLOOD, Config
from .state import State

PRUNE_EVERY = 10.0


class Detector:
    def __init__(self, config: Config | None = None, on_alert=None, enabled=RULES):
        self.config = config or Config()
        self.log = AlertLog(self._record)
        self.state = State(self.config.port_scan.window, self.config.syn_flood.window)
        self.now = 0.0
        self.peak: dict[str, str] = {}  # worst status each host has had
        self._on_alert = on_alert
        self._scan = PORT_SCAN in enabled
        self._flood = SYN_FLOOD in enabled
        self._arp = ARP_SPOOF in enabled
        self._allow = {rule: set(self.config.allowlist.get(rule, ())) for rule in RULES}
        self._next_prune = None

    @property
    def alerts(self) -> list[Alert]:
        return self.log.alerts

    def handle(self, pkt) -> None:
        """Entry point for a Scapy packet, from PcapReader or sniff(prn=...)."""
        self.handle_info(decode(pkt))

    def handle_info(self, p: PacketInfo) -> None:
        now = self.now = p.ts
        if p.src_mac is not None:
            self.state.mac_seen[p.src_mac] = now
        if p.kind == TCP_KIND:
            if self._scan or self._flood:
                self._tcp(p)
        elif p.kind == ARP_KIND and self._arp:
            rules.arp_spoof(self.config.arp_spoof, self._allow[ARP_SPOOF], self.log, self.state, p)

        if self._next_prune is None:
            self._next_prune = now + PRUNE_EVERY
        elif now >= self._next_prune:
            self.state.prune(now)
            self._next_prune = now + PRUNE_EVERY

    def _tcp(self, p: PacketInfo) -> None:
        flags = p.flags
        if flags & SYN:
            if flags & ACK:
                self.state.synack(p)
                return
            source, service = self.state.syn(p)
            if self._scan:
                rules.port_scan(self.config.port_scan, self._allow[PORT_SCAN], self.log,
                                p.ts, p.src_ip, source)
            if self._flood:
                rules.syn_flood(self.config.syn_flood, self._allow[SYN_FLOOD], self.log,
                                p.ts, p.dst_ip, p.dport, service)
        elif flags & RST:
            self.state.rst(p)
        elif flags & ACK:
            self.state.ack(p)

    def host_status(self, now: float | None = None) -> dict[str, dict]:
        """Each host's status is its most severe active alert, as actor or target."""
        now = self.now if now is None else now
        status = {ip: {"status": "ok", "alerts": []} for ip in self.state.bindings}
        for alert in self.log.active(now):
            for role, host in (("actor", alert.actor), ("target", alert.target)):
                if host is None:
                    continue
                entry = status.setdefault(host, {"status": "ok", "alerts": []})
                entry["alerts"].append({"id": alert.id, "rule": alert.rule, "role": role,
                                        "severity": alert.severity})
                if RANK[alert.severity] > RANK[entry["status"]]:
                    entry["status"] = alert.severity
        return status

    def _record(self, alert: Alert) -> None:
        for host in (alert.actor, alert.target):
            if host is not None and RANK[alert.severity] > RANK[self.peak.get(host, "ok")]:
                self.peak[host] = alert.severity
        if self._on_alert is not None:
            self._on_alert(alert)
