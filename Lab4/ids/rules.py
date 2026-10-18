"""The three detection rules and their configuration. Each rule looks only at its
own summary of recent traffic, so several can fire for the same host."""

import json
from collections import Counter
from dataclasses import asdict, dataclass, field

from .alerts import AlertLog
from .state import ArpBinding, ServiceWindow, SourceWindow, State

PORT_SCAN, SYN_FLOOD, ARP_SPOOF = "port_scan", "syn_flood", "arp_spoof"
RULES = (PORT_SCAN, SYN_FLOOD, ARP_SPOOF)

_NO_MAC = (None, "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")


@dataclass
class PortScanConfig:
    window: float = 30.0     # seconds of history per source
    threshold: int = 20      # distinct (host, port) pairs with an uncompleted attempt
    hold: float = 30.0       # seconds an alert stays active after the rule last fired
    severity: str = "medium"


@dataclass
class SynFloodConfig:
    window: float = 5.0
    threshold: int = 200                # SYNs to one (host, port) within the window
    min_incomplete_ratio: float = 0.5   # share of those whose handshake never completed
    hold: float = 30.0
    severity: str = "high"


@dataclass
class ArpSpoofConfig:
    stale_after: float = 30.0  # previous owner silent this long: treat a change as a replaced NIC
    hold: float = 60.0


@dataclass
class Config:
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    syn_flood: SynFloodConfig = field(default_factory=SynFloodConfig)
    arp_spoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)
    # Hosts a rule never alerts on: scanners by source IP, flood and ARP alerts by target IP.
    allowlist: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        return cls(
            port_scan=PortScanConfig(**data.get(PORT_SCAN, {})),
            syn_flood=SynFloodConfig(**data.get(SYN_FLOOD, {})),
            arp_spoof=ArpSpoofConfig(**data.get(ARP_SPOOF, {})),
            allowlist={rule: list(hosts) for rule, hosts in data.get("allowlist", {}).items()},
        )

    @classmethod
    def load(cls, path) -> "Config":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def to_dict(self) -> dict:
        return asdict(self)


def _scan_evidence(failed: dict) -> tuple[str, str | None, dict]:
    ports_by_host: dict[str, set] = {}
    for host, port in failed:
        ports_by_host.setdefault(host, set()).add(port)
    ports = set().union(*ports_by_host.values())
    top_host = max(ports_by_host, key=lambda h: len(ports_by_host[h]))
    sweep = len(ports_by_host) > len(ports)
    evidence = {
        "distinct_targets": len(failed),
        "distinct_hosts": len(ports_by_host),
        "distinct_ports": len(ports),
        "sample_ports": sorted(ports)[:10],
    }
    return ("portsweep" if sweep else "portscan"), (None if sweep else top_host), evidence


def port_scan(cfg: PortScanConfig, allow: set, log: AlertLog, now: float,
              src: str, window: SourceWindow) -> None:
    """One source with uncompleted connection attempts to many different ports or hosts."""
    count = len(window.failed)
    if count < cfg.threshold or src in allow:
        return
    key = (PORT_SCAN, src)
    # Evidence stays in the window for cfg.window seconds, so the alert has to as well.
    hold = max(cfg.hold, cfg.window)
    alert = log.refresh(key, now, hold, cfg.severity)
    if alert is None:
        subtype, target, evidence = _scan_evidence(window.failed)
        evidence.update(window=cfg.window, threshold=cfg.threshold)
        log.emit(key, now, hold, rule=PORT_SCAN, subtype=subtype, severity=cfg.severity,
                 actor=src, target=target, evidence=evidence)
    elif count > alert.evidence["distinct_targets"]:
        alert.evidence.update(_scan_evidence(window.failed)[2])


def syn_flood(cfg: SynFloodConfig, allow: set, log: AlertLog, now: float,
              dst: str, dport: int, window: ServiceWindow) -> None:
    """Many SYNs to one service where most handshakes never complete."""
    syns = len(window.attempts)
    if syns < cfg.threshold or dst in allow:
        return
    incomplete = syns - window.completed
    if incomplete < cfg.min_incomplete_ratio * syns:
        return
    key = (SYN_FLOOD, dst)
    hold = max(cfg.hold, cfg.window)
    alert = log.refresh(key, now, hold, cfg.severity)
    if alert is None:
        sources = Counter(c.src for c in window.attempts if not c.established)
        top, top_count = sources.most_common(1)[0] if sources else (None, 0)
        single = top_count >= 0.9 * max(incomplete, 1)
        log.emit(key, now, hold, rule=SYN_FLOOD,
                 subtype="single_source" if single else "many_sources",
                 severity=cfg.severity, actor=top if single else None, target=dst,
                 evidence={"port": dport, "syn_count": syns, "incomplete": incomplete,
                           "distinct_sources": len(sources), "window": cfg.window,
                           "threshold": cfg.threshold})
    elif syns > alert.evidence["syn_count"]:
        alert.evidence.update(syn_count=syns, incomplete=incomplete)


def arp_spoof(cfg: ArpSpoofConfig, allow: set, log: AlertLog, state: State, p) -> None:
    """An IP address whose MAC address changes (arpwatch: changed address, flip flop)."""
    ip, mac, now = p.src_ip, p.arp_mac, p.ts
    if not ip or ip == "0.0.0.0" or mac in _NO_MAC:
        return
    state.mac_owner.setdefault(mac, ip)
    binding = state.bindings.get(ip)
    if binding is None:
        state.bindings[ip] = ArpBinding(mac, now)
        return
    if mac == binding.mac:
        return

    old = binding.mac
    binding.mac = mac
    binding.changed_at = now
    key = (ARP_SPOOF, ip)
    if mac == binding.trusted:
        # The long-standing owner answering again is not a new claim.
        log.refresh(key, now, cfg.hold)
        return

    silent_for = now - state.mac_seen.get(old, binding.since)
    if mac == binding.contender:
        subtype, severity = "flip_flop", "high"
    elif silent_for <= cfg.stale_after:
        subtype, severity = "changed_address", "medium"
    else:
        # Previous owner has gone quiet: most likely replaced hardware or a failover.
        subtype, severity = "changed_address", "low"
        binding.trusted = mac
    if severity != "low":
        binding.contender = mac

    if ip in allow or log.refresh(key, now, cfg.hold, severity) is not None:
        return
    # A MAC that already answers for another IP is the likelier impostor.
    actor = mac
    for candidate in (mac, old):
        owner = state.mac_owner.get(candidate)
        if owner and owner != ip:
            actor = owner
            break
    log.emit(key, now, cfg.hold, rule=ARP_SPOOF, subtype=subtype, severity=severity,
             actor=actor, target=ip,
             evidence={"old_mac": old, "new_mac": mac,
                       "old_mac_silent_for": round(silent_for, 3),
                       "stale_after": cfg.stale_after})
