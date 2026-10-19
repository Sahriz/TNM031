"""The three detection rules and their configuration. Each rule looks only at its
own summary of recent traffic, so several can fire for the same host."""

import json
from collections import Counter
from dataclasses import asdict, dataclass, field

from .alerts import AlertLog
from .state import ArpBinding, ServiceWindow, SourceWindow, State

PORT_SCAN, SYN_FLOOD, ARP_SPOOF = "port_scan", "syn_flood", "arp_spoof"
RULES = (PORT_SCAN, SYN_FLOOD, ARP_SPOOF)

# Handwritten behavioral rules over recent traffic.
# They do not match payload signatures or learn a model. Each can fire separately;
# detector.py combines the resulting alerts using the highest active severity.
# Snort scan inspection, Suricata thresholds and arpwatch address changes inspired
# the approach; this code is not an implementation or benchmark of those products.
# port_scan() uses a fixed count and time window rather than a statistical model.
# Background references are in tnm031-lab4-resources.md.

_NO_MAC = (None, "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")


@dataclass
class PortScanConfig:
    # Fallback settings for missing configuration fields. run.py loads config.json,
    # whose supplied values override these defaults.
    window: float = 30.0     # seconds of history per source
    threshold: int = 20      # distinct (host, port) pairs with an uncompleted attempt
    hold: float = 30.0       # seconds an alert stays active after the rule last fired
    severity: str = "medium"


@dataclass
class SynFloodConfig:
    window: float = 5.0
    threshold: int = 200                # SYNs to one (host, port) within the window
    min_incomplete_ratio: float = 0.5   # share with no completed handshake observed so far
    hold: float = 30.0
    severity: str = "high"


@dataclass
class ArpSpoofConfig:
    stale_after: float = 30.0  # previous owner silent this long: treat a change as a replaced NIC
    hold: float = 60.0


@dataclass
class Config:
    # Group each rule's settings in its own configuration object.
    # default_factory creates a separate settings object for each Config instance.
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    syn_flood: SynFloodConfig = field(default_factory=SynFloodConfig)
    arp_spoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        # ** passes JSON fields as named arguments, e.g. window=300, threshold=30.
        # Missing sections use defaults; a misspelled field is rejected by Python.
        return cls(
            port_scan=PortScanConfig(**data.get(PORT_SCAN, {})),
            syn_flood=SynFloodConfig(**data.get(SYN_FLOOD, {})),
            arp_spoof=ArpSpoofConfig(**data.get(ARP_SPOOF, {})),
        )

    @classmethod
    def load(cls, path) -> "Config":
        with open(path, encoding="utf-8") as file:
            return cls.from_dict(json.load(file))

    def to_dict(self) -> dict:
        return asdict(self)


def _scan_evidence(incomplete_targets: dict) -> tuple[str, str | None, dict]:
    # Summarize an already-triggered scan; this does not apply another threshold.
    # More distinct hosts than ports is called a portsweep; otherwise portscan.
    # That subtype is a simple descriptive heuristic, not a complete scan taxonomy.
    ports_by_host: dict[str, set] = {}
    ports = set()
    for host, port in incomplete_targets:
        if host not in ports_by_host:
            ports_by_host[host] = set()
        ports_by_host[host].add(port)
        ports.add(port)
    top_host = max(ports_by_host, key=lambda host: len(ports_by_host[host]))
    if len(ports_by_host) > len(ports):
        subtype = "portsweep"
        target = None
    else:
        subtype = "portscan"
        target = top_host
    evidence = {
        "distinct_targets": len(incomplete_targets),
        "distinct_hosts": len(ports_by_host),
        "distinct_ports": len(ports),
        "sample_ports": sorted(ports)[:10],
    }
    return subtype, target, evidence


def port_scan(config: PortScanConfig, log: AlertLog, now: float,
              source_ip: str, window: SourceWindow) -> None:
    """One source with uncompleted connection attempts to many different ports or hosts."""
    # State.record_syn() has already expired old entries and added
    # this attempt. Count distinct (destination IP, port) pairs, not raw SYNs.
    # The supplied config.json uses 30 pairs within 300 seconds; completed attempts
    # are removed by State.record_ack(). See the scan tests in tests/test_rules.py.
    count = len(window.incomplete_targets)
    # Returning here means "not enough evidence". Equality reaches the threshold.
    if count < config.threshold:
        return
    key = (PORT_SCAN, source_ip)
    # A source is evaluated independently: slow/small scans may stay below the
    # threshold, and distributed scans can split their probes among many sources.
    # Keep the alert active for at least as long as its supporting evidence.
    hold = max(config.hold, config.window)
    alert = log.refresh(key, now, hold, config.severity)
    if alert is None:
        subtype, target, evidence = _scan_evidence(window.incomplete_targets)
        evidence.update(window=config.window, threshold=config.threshold)
        log.emit(key, now, hold, rule=PORT_SCAN, subtype=subtype, severity=config.severity,
                 actor=source_ip, target=target, evidence=evidence)
    elif count > alert.evidence["distinct_targets"]:
        # Retain evidence from the largest observed breadth while the alert is
        # active. The record's original timestamp still marks the first trigger.
        subtype, target, evidence = _scan_evidence(window.incomplete_targets)
        alert.evidence.update(evidence)


def syn_flood(config: SynFloodConfig, log: AlertLog, now: float,
              destination_ip: str, destination_port: int, window: ServiceWindow) -> None:
    """Many SYNs to one service with a high share of handshakes still incomplete."""
    # Both conditions must pass: enough SYN attempts in the window,
    # and a high enough incomplete share. The supplied settings are 100 SYNs in
    # five seconds and at least 80% incomplete. Retransmitted SYNs count too.
    # A normal connection burst can have high volume but mostly completed handshakes.
    syn_count = len(window.attempts)
    if syn_count < config.threshold:
        return
    incomplete_count = syn_count - window.completed_count
    # Multiplication compares the share without division. "Incomplete" is what
    # we have observed so far: latency/loss/missing replies can also cause it.
    # This reports flood-like behavior; it does not measure the victim's capacity.
    if incomplete_count < config.min_incomplete_ratio * syn_count:
        return
    key = (SYN_FLOOD, destination_ip)
    # Measurements are per service (IP + port), but alert records are grouped by
    # destination IP. Simultaneous findings on different ports can share a record.
    hold = max(config.hold, config.window)
    alert = log.refresh(key, now, hold, config.severity)
    if alert is None:
        sources = Counter()
        for connection in window.attempts:
            if not connection.handshake_complete:
                sources[connection.source_ip] += 1
        top_source = None
        top_count = 0
        if sources:
            top_source, top_count = sources.most_common(1)[0]
        if top_count >= 0.9 * max(incomplete_count, 1):
            # Attribute a single source only if it contributes at least 90% of
            # incomplete attempts. Otherwise keep the victim but no single actor.
            subtype = "single_source"
            actor = top_source
        else:
            subtype = "many_sources"
            actor = None
        log.emit(key, now, hold, rule=SYN_FLOOD,
                 subtype=subtype,
                 severity=config.severity, actor=actor, target=destination_ip,
                 evidence={"port": destination_port, "syn_count": syn_count, "incomplete": incomplete_count,
                           "distinct_sources": len(sources), "window": config.window,
                           "threshold": config.threshold})
    elif syn_count > alert.evidence["syn_count"]:
        alert.evidence.update(syn_count=syn_count, incomplete=incomplete_count)


def arp_spoof(config: ArpSpoofConfig, log: AlertLog, state: State, packet) -> None:
    """An IP address whose MAC address changes (arpwatch: changed address, flip flop)."""
    # Compare the IP-to-MAC claim with the last claim we observed.
    # ARP has legitimate address changes too, so a change alone is not proof of
    # interception. decode() supplies these sender fields from the ARP header.
    ip = packet.source_ip
    mac = packet.arp_sender_mac
    now = packet.timestamp
    if not ip or ip == "0.0.0.0" or mac in _NO_MAC:
        # A probe for an address may use 0.0.0.0. It is not an ownership change.
        return
    state.mac_owner.setdefault(mac, ip)
    binding = state.bindings.get(ip)
    if binding is None:
        # First observation establishes a baseline; there is no earlier claim to
        # compare. An already-poisoned initial observation cannot be identified here.
        state.bindings[ip] = ArpBinding(mac, now)
        return
    if mac == binding.mac:
        return

    previous_mac = binding.mac
    binding.mac = mac
    binding.changed_at = now
    key = (ARP_SPOOF, ip)
    if mac == binding.trusted:
        # The long-standing owner answering again is not a new claim.
        log.refresh(key, now, config.hold)
        return

    silent_for = now - state.mac_seen.get(previous_mac, binding.since)
    # Severity follows three evidence levels, covered in tests/test_rules.py.
    # High: the same competing MAC claims the address again after ownership changes.
    # Medium: a new claim while the previous MAC was recently active.
    # Low: the previous MAC was quiet, consistent with replacement or failover.
    # A quiet-host attack can therefore be reported only as low severity and missed
    # by the scored evaluation, which excludes low alerts. See evaluate.match().
    if mac == binding.contender:
        subtype, severity = "flip_flop", "high"
    elif silent_for <= config.stale_after:
        subtype, severity = "changed_address", "medium"
    else:
        # Previous owner has gone quiet: most likely replaced hardware or a failover.
        subtype, severity = "changed_address", "low"
        binding.trusted = mac
    if severity != "low":
        binding.contender = mac

    if log.refresh(key, now, config.hold, severity) is not None:
        return
    # A MAC that already answers for another IP is the likelier impostor.
    # This actor attribution is a heuristic based on earlier observed claims,
    # not verified identity; fall back to the MAC when an IP cannot be inferred.
    actor = mac
    for candidate in (mac, previous_mac):
        owner = state.mac_owner.get(candidate)
        if owner and owner != ip:
            actor = owner
            break
    log.emit(key, now, config.hold, rule=ARP_SPOOF, subtype=subtype, severity=severity,
             actor=actor, target=ip,
             evidence={"old_mac": previous_mac, "new_mac": mac,
                       "old_mac_silent_for": round(silent_for, 3),
                       "stale_after": config.stale_after})
