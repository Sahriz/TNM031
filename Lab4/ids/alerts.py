"""Alert records, rate-limiting and the JSON lines writer."""

import json
from dataclasses import dataclass, field

RANK = {"ok": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Alert:
    # rule/subtype explain what triggered, severity is its level,
    # actor/target identify participants, and evidence holds the measured counts
    # or address change. These are reports of suspicious behavior, not verdicts.
    id: int
    timestamp: float
    rule: str
    subtype: str
    severity: str
    actor: str | None
    target: str | None
    evidence: dict = field(default_factory=dict)
    last_seen: float = 0.0
    active_until: float = 0.0
    count: int = 1  # times the rule re-triggered while this alert was active

    # timestamp = first trigger; last_seen = latest refresh; active_until = expiry.
    # count includes the first emission plus refreshes, not separate attack events.

    def to_dict(self) -> dict:
        # Python uses timestamp; JSON keeps the existing field name "ts".
        # Evidence may reflect a later traffic peak, not only the first trigger.
        return {
            "id": self.id,
            "ts": round(self.timestamp, 6),
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

    def __init__(self):
        self.alerts: list[Alert] = []
        self._current: dict[tuple, Alert] = {}

    def refresh(self, key: tuple, now: float, hold: float, severity: str = "low") -> Alert | None:
        """Extend the active alert for key. Returns None if a new alert should be
        emitted: nothing is active, or the new severity is higher (escalation)."""
        # Repeated matching traffic extends one active finding.
        # Return None when the rule should emit a new record: first occurrence,
        # expired finding, or higher severity. Lower severity does not downgrade it.
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
        # The full list preserves history. _current holds the latest finding per
        # key for refresh and host_status(); an escalation replaces that entry.
        alert = Alert(id=len(self.alerts) + 1, timestamp=now, rule=rule, subtype=subtype,
                      severity=severity, actor=actor, target=target, evidence=evidence,
                      last_seen=now, active_until=now + hold)
        self.alerts.append(alert)
        self._current[key] = alert
        return alert

    def active(self, now: float) -> list[Alert]:
        return [alert for alert in self._current.values() if alert.active_until >= now]


def write_jsonl(alerts: list[Alert], path) -> None:
    # JSON Lines stores one complete JSON object per line, so each
    # finding can be inspected separately. run.py calls this after the capture.
    with open(path, "w", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert.to_dict()) + "\n")
