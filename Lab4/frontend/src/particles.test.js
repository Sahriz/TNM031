import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_PARTICLES, TRAIL_SECONDS, networkLayout, packetWindow, routeFor, pointOnRoute, upperBound, probeActivity, threatJump } from './particles.js';

const packet = (t, from = 'a', to = 'b') => [t, from, to, 'tcp', 'ok', 60];
const positions = new Map([['a', { id: 'a', x: 0, y: 0 }], ['b', { id: 'b', x: 600, y: 0 }]]);

test('emission uses captured timestamps, includes simultaneous packets, and excludes the future', () => {
  const events = [packet(0), packet(.1), packet(.1), packet(.101), packet(6)];
  assert.equal(upperBound(events, .1), 3);
  assert.deepEqual(packetWindow(events, .1).indices, [0, 1, 2]);
  assert.deepEqual(packetWindow(events, 5).indices, []);
  assert.deepEqual(packetWindow(events, 0).indices, [0]); // seek backwards clears later packets
});

test('forward and return packets use their actual endpoints and separate lanes', () => {
  const request = routeFor(packet(0), positions), reply = routeFor(packet(0, 'b', 'a'), positions);
  assert.deepEqual(pointOnRoute(request, 0), { x: 0, y: 0 });
  assert.deepEqual(pointOnRoute(request, 1), { x: 600, y: 0 });
  assert.deepEqual(pointOnRoute(reply, 0), { x: 600, y: 0 });
  assert.ok(pointOnRoute(request, .5).y > 0);
  assert.ok(pointOnRoute(reply, .5).y < 0);
  assert.deepEqual(pointOnRoute(request, .5), pointOnRoute(request, .5)); // paused/seek projection is deterministic
});

test('default mode retains every packet in a dense burst; sampling is explicit', () => {
  const events = Array.from({ length: 60000 }, (_, i) => packet(i / 3000));
  const all = packetWindow(events, 15);
  assert.equal(all.sampled, false);
  assert.equal(all.indices.length, 3000);
  assert.equal(all.indices.length, all.total);
  assert.ok(all.indices.every(i => events[i][0] <= 15 && events[i][0] > 15 - TRAIL_SECONDS));
  const sampled = packetWindow(events, 15, 'sampled');
  assert.ok(sampled.indices.length <= MAX_PARTICLES);
  assert.equal(sampled.sampled, true);
  assert.equal(sampled.total, all.total);
});

test('visual journeys finish within one second at 1x, including loops and long paths', () => {
  const routes = [routeFor(packet(0), positions), routeFor(packet(0, 'a', 'a'), positions),
    routeFor(packet(0), new Map([['a', { id: 'a', x: 0, y: 0 }], ['b', { id: 'b', x: 1200, y: 570 }]]))];
  for (const route of routes) {
    assert.ok(route.duration > 0 && route.duration <= 1);
    assert.ok(route.duration <= TRAIL_SECONDS);
    assert.deepEqual(pointOnRoute(route, 1), { x: route.target.x, y: route.target.y });
  }
});

test('broadcasts have a destination distinct from the sender and hidden addresses are grouped', () => {
  const hosts = Array.from({ length: 30 }, (_, i) => ({ id: `host${i}`, name: `host${i}`, known: false, sent: 1, received: 1 }));
  const layout = networkLayout({ hosts, alerts: [], packet_events: [[0, 'host0', '__broadcast', 'arp', 'ok', 42]] });
  const route = routeFor([0, 'host0', '__broadcast'], layout.positions);
  assert.equal(route.source.id, 'host0');
  assert.equal(route.target.id, '__broadcast');
  assert.equal(routeFor([0, 'host29', 'host0'], layout.positions).source.id, '__other');
  assert.equal(layout.positions.get('__other').count, 8);
  assert.equal(routeFor([0, 'host0', 'host0'], layout.positions).loop, true);
  const internal = routeFor([0, 'host28', 'host29'], layout.positions);
  assert.equal(internal.loop, true);
  assert.notDeepEqual(pointOnRoute(internal, .5), pointOnRoute(internal, 0));
});

test('simultaneous packets separate spatially without delaying their emission', () => {
  const route = routeFor(packet(0), positions);
  assert.notDeepEqual(pointOnRoute(route, .5, 10), pointOnRoute(route, .5, 11));
  assert.deepEqual(pointOnRoute(route, 0, 10), pointOnRoute(route, 0, 11));
});

test('probe activity distinguishes scan breadth from flood volume and excludes responses and the future', () => {
  const scan = Array.from({ length: 106 }, (_, i) => [...packet(1 + i / 400), 40000, i + 1, 2]);
  const reply = [...packet(1.1, 'b', 'a'), 80, 40000, 18];
  const future = [...packet(4), 40000, 9000, 2];
  const events = [...scan, reply, future].sort((a,b) => a[0] - b[0]);
  const activity = probeActivity(events, 2, null, positions);
  assert.equal(activity.probes, 106);
  assert.equal(activity.ports.length, 106);
  assert.equal(activity.targets, 1);
  assert.equal(probeActivity(events, 15, null, positions).probes, 0);
  const flood = scan.map(p => [...p.slice(0, 7), 80, 2]);
  assert.equal(probeActivity(flood, 2, null, positions).ports.length, 1);
  assert.equal(probeActivity(flood, 2, null, positions).probes, 106);
});

test('threat jump includes the lead-in, slows scans, and advances when clicked again', () => {
  const report = { start: 100, alerts: [
    { id: 1, ts: 102, severity: 'low', rule: 'arp_spoof' },
    { id: 2, ts: 110.08, severity: 'medium', rule: 'port_scan' },
    { id: 3, ts: 120, severity: 'high', rule: 'syn_flood' }] };
  const first = threatJump(report, 0, null);
  assert.ok(first.time < 10);
  assert.equal(first.speed, .25);
  assert.equal(first.alert.id, 2);
  assert.equal(threatJump(report, first.time, first.alert.id).alert.id, 3);
  assert.equal(threatJump({ ...report, alerts: [] }, 0), null);
});
