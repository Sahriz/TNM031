"""Alert records, rate-limiting and the JSON lines writer."""

import json
from dataclasses import dataclass, field

RANK = {"ok": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Alert:
    id: int
    ts: float
    rule: str
    subtype: str
    severity: str
    actor: str | None
    target: str | None
    evidence: dict = field(default_factory=dict)
    last_seen: float = 0.0
    active_until: float = 0.0
    count: int = 1  # times the rule re-triggered while this alert was active

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": round(self.ts, 6),
            "last_seen": round(self.last_seen, 6),
            "active_until": round(self.active_until, 6),
            "rule": self.rule,
            "subtype": self.subtype,
            "severity": self.severity,
            "actor": self.actor,
            "target": self.target,
            "count": self.count,
            "evidence": self.evidence,
        }


class AlertLog:
    """One alert per key while it stays active; repeats only extend it."""

    def __init__(self, on_alert=None):
        self.alerts: list[Alert] = []
        self._current: dict[tuple, Alert] = {}
        self._on_alert = on_alert

    def refresh(self, key: tuple, now: float, hold: float, severity: str = "low") -> Alert | None:
        """Extend the active alert for key. Returns None if a new alert should be
        emitted: nothing is active, or the new severity is higher (escalation)."""
        alert = self._current.get(key)
        if alert is None or now > alert.active_until:
            return None
        if RANK[severity] > RANK[alert.severity]:
            return None
        alert.last_seen = now
        alert.active_until = now + hold
        alert.count += 1
        return alert

    def emit(self, key: tuple, now: float, hold: float, *, rule: str, subtype: str,
             severity: str, actor: str | None, target: str | None, evidence: dict) -> Alert:
        alert = Alert(len(self.alerts) + 1, now, rule, subtype, severity, actor, target,
                      evidence, last_seen=now, active_until=now + hold)
        self.alerts.append(alert)
        self._current[key] = alert
        if self._on_alert is not None:
            self._on_alert(alert)
        return alert

    def active(self, now: float) -> list[Alert]:
        return [a for a in self._current.values() if a.active_until >= now]


def write_jsonl(alerts: list[Alert], path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert.to_dict()) + "\n")
