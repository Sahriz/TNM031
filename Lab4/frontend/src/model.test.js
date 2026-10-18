import test from 'node:test';
import assert from 'node:assert/strict';
import { detectionMarkers, filterAlerts, frameAt, networkStateAt, parseImport, statuses, validateReport } from './model.js';

const alert = { id: 1, ts: 100, rule: 'port_scan', subtype: 'portsweep', severity: 'medium', actor: '10.0.0.1', target: null,
  evidence: { distinct_targets: 30 }, last_seen: 102, active_until: 110, count: 2 };

test('network flags a subsecond detection immediately and never exposes final evidence', () => {
  const report = { start: 100, alerts: [{ ...alert, ts: 100.2 }], detection_events: [[0, []], [.2, [1]], [3, []]] };
  assert.equal(networkStateAt(report, .199).alerts.length, 0);
  const state = networkStateAt(report, .25);
  assert.equal(state.alerts.length, 1);
  assert.equal(state.alerts[0].evidence, undefined);
  assert.equal(state.alerts[0].count, undefined);
  assert.equal(statuses(state)['10.0.0.1'], 'medium');
  assert.equal(networkStateAt(report, 3).alerts.length, 0);
});

test('timeline lookup never chooses a future snapshot', () => {
  const report = { frames: [{ t: 0 }, { t: 1 }, { t: 2.7 }] };
  assert.equal(frameAt(report, 2.6).t, 1);
  assert.equal(frameAt(report, 2.7).t, 2.7);
  assert.equal(frameAt(report, 0).t, 0);
});

test('node highlights mark new detections, not the entire retained-alert lifetime', () => {
  const scan = { ...alert, ts: 100.2, last_seen: 190, active_until: 490 };
  const arp = { ...alert, id: 2, rule: 'arp_spoof', severity: 'high', ts: 110 };
  const report = { start: 100, alerts: [scan, arp], detection_events: [[0, []], [.2, [1]], [10, [1, 2]], [70, [1]], [390, []]] };
  const markers = time => detectionMarkers(networkStateAt(report, time), report.start, time);
  assert.deepEqual(markers(.199), []);
  assert.equal(markers(.2)[0].phase, 'new');
  assert.equal(markers(3.199)[0].phase, 'new');
  assert.equal(markers(3.2)[0].phase, 'retained');
  assert.deepEqual(markers(10).map(a => [a.rule, a.phase]), [['port_scan', 'retained'], ['arp_spoof', 'new']]);
  assert.deepEqual(markers(80).map(a => a.phase), ['retained']);
  assert.deepEqual(markers(390), []);
  // Rewinding must restore the detection cue without leaking future refresh times.
  assert.equal(markers(.25)[0].phase, 'new');
  assert.equal(markers(.25)[0].last_seen, undefined);
});

test('legacy snapshot markers exclude inactive, informational and future alerts', () => {
  const frame = { active_ids: [1, 2, 3], alerts: [alert, { ...alert, id: 2, severity: 'low' },
    { ...alert, id: 3, ts: 120 }, { ...alert, id: 4 }] };
  assert.deepEqual(detectionMarkers(frame, 100, 10).map(a => [a.id, a.phase]), [[1, 'retained']]);
});

test('host status includes simultaneous rules and ignores expired alerts', () => {
  const flood = { ...alert, id: 2, rule: 'syn_flood', target: '10.0.0.2', severity: 'high' };
  assert.deepEqual(statuses({ alerts: [alert, flood], active_ids: [1, 2] }), { '10.0.0.1': 'high', '10.0.0.2': 'high' });
  assert.deepEqual(statuses({ alerts: [alert, flood], active_ids: [1] }), { '10.0.0.1': 'medium' });
});

test('search, rule, and severity filters combine', () => {
  assert.equal(filterAlerts([alert], { query: '10.0.0.1', rule: 'port_scan', severity: 'medium' }).length, 1);
  assert.equal(filterAlerts([alert], { query: 'unknown' }).length, 0);
  assert.equal(filterAlerts([alert], { severity: 'high' }).length, 0);
});

test('JSONL import is explicitly a summary without invented traffic or scores', () => {
  const report = parseImport(JSON.stringify(alert), 'alerts.jsonl');
  assert.equal(report.mode, 'alert-log');
  assert.equal(report.packet_count, null);
  assert.equal(report.evaluation, null);
  assert.deepEqual(report.frames[0].active_ids, []);
  assert.equal(report.hosts.length, 1);
});

test('invalid input and duplicate IDs report useful errors', () => {
  assert.throws(() => parseImport('', 'a.jsonl'), /empty/);
  assert.throws(() => parseImport('garbage', 'a.json'), /JSON/);
  assert.throws(() => parseImport('{}', 'a.json'), /valid Netpulse/);
  assert.throws(() => parseImport('{}', 'a.jsonl'), /alert is missing/);
  assert.throws(() => parseImport([alert, alert].map(a => JSON.stringify(a)).join('\n'), 'a.jsonl'), /unique/);
});

test('reports reject invalid frames before rendering', () => {
  const report = parseImport(JSON.stringify(alert), 'alerts.jsonl');
  report.frames[0].t = -1;
  assert.throws(() => validateReport(report), /valid Netpulse/);
});

test('packet imports reject reversed timestamps and invalid routing or severity', () => {
  const report = parseImport(JSON.stringify(alert), 'alerts.jsonl');
  report.duration = 3;
  report.packet_events = [[0, 'a', 'b', 'tcp', 'ok', 60], [2, 'b', 'a', 'udp', 'high', 100]];
  assert.equal(validateReport(report), report);
  for (const invalid of [[-1, 'a', 'b', 'tcp', 'ok', 60], [4, 'a', 'b', 'tcp', 'ok', 60],
    [0, '', 'b', 'tcp', 'ok', 60], [0, 'a', 'b', 'tcp', 'critical', 60]]) {
    assert.throws(() => validateReport({ ...report, packet_events: [invalid] }), /valid Netpulse/);
  }
  assert.throws(() => validateReport({ ...report, packet_events: [...report.packet_events].reverse() }), /valid Netpulse/);
  assert.equal(validateReport({ ...report, packet_events: [[0, 'a', 'b', 'tcp', 'ok', 60, 40000, 443, 2]] }).packet_events[0][7], 443);
  assert.throws(() => validateReport({ ...report, packet_events: [[0, 'a', 'b', 'tcp', 'ok', 60, 40000, 70000, 2]] }), /valid Netpulse/);
});
