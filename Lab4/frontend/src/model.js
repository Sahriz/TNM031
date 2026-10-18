export const RULES = { port_scan: 'Port scan', syn_flood: 'SYN flood', arp_spoof: 'ARP spoofing' };
export const RANK = { ok: 0, low: 1, medium: 2, high: 3 };
export const COLORS = { ok: '#84dbba', low: '#78aef0', medium: '#edbd70', high: '#f17c87' };
export const formatNumber = value => value == null ? '—' : new Intl.NumberFormat('en-US').format(value);
export const clock = seconds => `${String(Math.floor(Math.max(0, seconds) / 60)).padStart(2, '0')}:${String(Math.floor(Math.max(0, seconds) % 60)).padStart(2, '0')}`;
export const humanize = text => String(text).replaceAll('_', ' ');
export const bytes = n => n == null ? '—' : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e3).toFixed(1)} kB`;

export function frameAt(report, time) {
  let lo = 0, hi = report.frames.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (report.frames[mid].t <= time) lo = mid;
    else hi = mid - 1;
  }
  return report.frames[lo];
}

export function statuses(frame) {
  const result = {};
  const active = new Set(frame.active_ids);
  for (const alert of frame.alerts) {
    if (!active.has(alert.id)) continue;
    for (const host of [alert.actor, alert.target]) {
      if (host && RANK[alert.severity] > RANK[result[host] || 'ok']) result[host] = alert.severity;
    }
  }
  return result;
}

// This is a display cue for a detection, not an estimate of an attack's duration.
export const DETECTION_HIGHLIGHT_SECONDS = 3;
export function detectionMarkers(frame, start, time) {
  const active = new Set(frame.active_ids);
  return frame.alerts.filter(a => active.has(a.id) && RANK[a.severity] >= 2 && a.ts <= start + time)
    .map(a => ({ ...a, phase: start + time - a.ts < DETECTION_HIGHLIGHT_SECONDS ? 'new' : 'retained' }));
}

export function networkStateAt(report, time) {
  if (!report.detection_events) return frameAt(report, time);
  let low = 0, high = report.detection_events.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (report.detection_events[middle][0] <= time) low = middle + 1;
    else high = middle;
  }
  const active_ids = report.detection_events[low - 1]?.[1] || [];
  // Only immutable identity fields are used; final counts/evidence must not leak into replay.
  const alerts = report.alerts.filter(a => active_ids.includes(a.id) && a.ts <= report.start + time)
    .map(({ id, ts, rule, severity, actor, target }) => ({ id, ts, rule, severity, actor, target }));
  return { t: time, active_ids, alerts };
}

export function filterAlerts(alerts, { rule = 'all', severity = 'all', query = '' }) {
  const search = query.trim().toLowerCase();
  return alerts.filter(a => (rule === 'all' || a.rule === rule) && (severity === 'all' || a.severity === severity)
    && `${RULES[a.rule]} ${a.subtype} ${a.actor || ''} ${a.target || ''}`.toLowerCase().includes(search));
}

const finite = n => typeof n === 'number' && Number.isFinite(n);
const object = o => o !== null && typeof o === 'object' && !Array.isArray(o);
function checkAlert(a) {
  if (!object(a) || !Number.isInteger(a.id) || !Object.hasOwn(RULES, a.rule)
    || !['low', 'medium', 'high'].includes(a.severity) || !finite(a.ts) || typeof a.subtype !== 'string'
    || ![a.actor, a.target].every(v => v == null || typeof v === 'string') || !object(a.evidence)
    || !finite(a.active_until) || !finite(a.last_seen) || !finite(a.count)) {
    throw new Error('An alert is missing valid timestamps, severity, rule, or evidence. Use an export from this detector.');
  }
}

export function validateReport(report) {
  const fail = () => { throw new Error('This is not a valid Netpulse report. Import a report from dashboard.py or an alerts.jsonl file.'); };
  if (!object(report) || report.schema !== 'netpulse-report-v1' || typeof report.name !== 'string'
    || typeof report.id !== 'string' || typeof report.source !== 'string' || !finite(report.start)
    || !finite(report.duration) || report.duration < 0 || !finite(report.interval) || report.interval <= 0
    || !Array.isArray(report.frames) || !report.frames.length || report.frames.length > 20001
    || !Array.isArray(report.alerts) || !Array.isArray(report.hosts) || !Array.isArray(report.events)) fail();
  report.alerts.forEach(checkAlert);
  if (report.detection_events !== undefined) {
    if (!Array.isArray(report.detection_events)) fail();
    let eventTime = -1;
    const known = new Set(report.alerts.map(a => a.id));
    for (const event of report.detection_events) {
      if (!Array.isArray(event) || event.length !== 2 || !finite(event[0]) || event[0] < 0
        || event[0] < eventTime || event[0] > report.duration + .001 || !Array.isArray(event[1])
        || event[1].some(id => !known.has(id))) fail();
      eventTime = event[0];
    }
  }
  if (report.packet_events !== undefined) {
    if (!Array.isArray(report.packet_events)) fail();
    let packetTime = -1;
    for (const packet of report.packet_events) {
      if (!Array.isArray(packet) || ![6, 9].includes(packet.length) || !finite(packet[0]) || packet[0] < 0
        || packet[0] < packetTime || packet[0] > report.duration + .001
        || ![packet[1], packet[2]].every(v => typeof v === 'string' && v.length > 0)
        || !['tcp', 'udp', 'arp', 'other'].includes(packet[3]) || !Object.hasOwn(RANK, packet[4])
        || !finite(packet[5]) || packet[5] < 0) fail();
      if (packet.length === 9 && (![packet[6], packet[7]].every(v => Number.isInteger(v) && v >= 0 && v <= 65535)
        || !Number.isInteger(packet[8]) || packet[8] < 0 || packet[8] > 511)) fail();
      packetTime = packet[0];
    }
  }
  let previous = -1;
  report.frames.forEach(f => {
    if (!object(f) || !finite(f.t) || f.t < 0 || f.t < previous || f.t > report.duration + .001 || !Array.isArray(f.alerts)
      || !Array.isArray(f.active_ids) || !object(f.traffic) || !Array.isArray(f.traffic.links)
      || !object(f.traffic.protocols) || !finite(f.traffic.packets)) fail();
    f.alerts.forEach(checkAlert);
    if (f.traffic.links.some(link => !Array.isArray(link) || link.length !== 3 || typeof link[0] !== 'string' || typeof link[1] !== 'string' || !finite(link[2]))) fail();
    previous = f.t;
  });
  if (report.frames[0].t !== 0 && report.mode !== 'alert-log') fail();
  report.hosts.forEach(h => { if (!object(h) || typeof h.id !== 'string' || typeof h.name !== 'string' || (h.mac != null && typeof h.mac !== 'string') || !finite(h.first_seen) || !finite(h.sent) || !finite(h.received) || !finite(h.bytes)) fail(); });
  report.events.forEach(e => { if (!object(e) || !['attack', 'benign'].includes(e.kind) || !Object.hasOwn(RULES, e.rule) || typeof e.subtype !== 'string' || !finite(e.start) || !finite(e.end) || !Array.isArray(e.actors) || !Array.isArray(e.targets)) fail(); });
  if (report.evaluation !== null) {
    const e = report.evaluation;
    if (!object(e) || !object(e.overall) || !object(e.rules) || !['detected_event_ids', 'false_positive_ids', 'late_ids', 'informational_ids'].every(k => Array.isArray(e[k]))) fail();
    for (const metric of [e.overall, ...Object.keys(RULES).map(r => e.rules[r])]) {
      if (!object(metric) || !['detected', 'missed', 'false_positives', 'precision', 'recall', 'f_half'].every(k => finite(metric[k]))) fail();
    }
  }
  return report;
}

export function parseImport(text, filename) {
  if (!text.trim()) throw new Error('This file is empty. Choose a report or alert log with data.');
  if (!filename.toLowerCase().endsWith('.jsonl')) {
    let report;
    try { report = JSON.parse(text); } catch { throw new Error('The file could not be read as JSON.'); }
    return validateReport(report);
  }
  let alerts;
  try { alerts = text.trim().split(/\r?\n/).map(line => JSON.parse(line)); }
  catch { throw new Error('The alert log must contain one JSON object per line.'); }
  alerts.forEach(checkAlert);
  alerts.sort((a, b) => a.ts - b.ts);
  if (new Set(alerts.map(a => a.id)).size !== alerts.length) throw new Error('Alert IDs must be unique. Import one detector run at a time.');
  const start = alerts[0].ts, end = alerts.at(-1).ts;
  const hosts = [...new Set(alerts.flatMap(a => [a.actor, a.target]).filter(Boolean))].map(id => ({
    id, name: id, local: false, known: false, first_seen: 0, sent: 0, received: 0, bytes: 0,
  }));
  return validateReport({ schema: 'netpulse-report-v1', mode: 'alert-log', id: `import-${filename}`, name: filename,
    source: 'Imported alert log', start, duration: end - start, interval: 1, hosts, alerts, events: [], evaluation: null,
    packet_count: null, byte_count: null, config: null,
    frames: [{ t: end - start, alerts, active_ids: [], packets_total: null, bytes_total: null,
      traffic: { packets: 0, protocols: {}, links: [] } }],
  });
}

export function initialTime(report) {
  if (report.mode === 'alert-log') return report.duration;
  const firstHigh = report.alerts.find(a => a.severity === 'high');
  return firstHigh ? Math.min(report.duration, Math.ceil(firstHigh.ts - report.start) + 3) : report.duration;
}

export function download(data, filename, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
