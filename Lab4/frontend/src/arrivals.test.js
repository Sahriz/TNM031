import test from 'node:test';
import assert from 'node:assert/strict';
import { ARRIVAL_GAP, IMPACT_SECONDS, buildArrivals, arrivalStateAt, impactScale } from './arrivals.js';
import { routeFor } from './particles.js';

const packet = (t, from = 'a', to = 'b') => [t, from, to, 'tcp', 'ok', 60];
const positions = new Map([['a', { id: 'a', x: 0, y: 0 }], ['b', { id: 'b', x: 600, y: 0 }],
  ['near', { id: 'near', x: 590, y: 0 }], ['__other', { id: '__other', x: 200, y: 200 }],
  ['__broadcast', { id: '__broadcast', x: 300, y: 0 }]]);

test('hits occur on arrival, count simultaneous packets, and rewind deterministically', () => {
  const events = [packet(0), packet(.1), packet(.1), packet(4)];
  const rows = buildArrivals(events, positions).get('b');
  const first = routeFor(events[0], positions).duration;
  assert.equal(arrivalStateAt(rows, first - .001).received, 0);
  assert.equal(arrivalStateAt(rows, first).received, 1);
  const paused = arrivalStateAt(rows, first + .1);
  assert.equal(paused.received, 3);
  assert.equal(paused.burst, 3);
  assert.deepEqual(arrivalStateAt(rows, first + .1), paused);
  assert.equal(arrivalStateAt(rows, 20).received, 4);
  assert.equal(arrivalStateAt(rows, first).received, 1);
  assert.equal(arrivalStateAt(rows, 0).received, 0);
});

test('different journey durations sort by landing time, not send order', () => {
  const events = [packet(0), packet(.01, 'near', 'b')];
  const rows = buildArrivals(events, positions).get('b');
  assert.equal(rows[0][2], 1);
  assert.equal(rows[1][2], 0);
  assert.equal(arrivalStateAt(rows, rows[0][0]).received, 1);
  assert.equal(arrivalStateAt(rows, rows[0][0]).packetIndex, 1);
  assert.equal(arrivalStateAt(rows, rows[1][0]).burst, 2);
});

test('a quiet gap ends the burst while the received total remains', () => {
  const rows = buildArrivals([packet(0), packet(ARRIVAL_GAP), packet(4)], positions).get('b');
  assert.equal(rows[1][1], 2);
  const quiet = arrivalStateAt(rows, rows[1][0] + ARRIVAL_GAP + .001);
  assert.equal(quiet.burst, 0);
  assert.equal(quiet.received, 2);
  assert.equal(arrivalStateAt(rows, rows[2][0]).burst, 1);
  assert.equal(arrivalStateAt(rows, rows[2][0]).received, 3);
});

test('broadcasts, grouped destinations and internal loops each count once at the destination', () => {
  const rows = buildArrivals([packet(0, 'a', '__broadcast'), packet(0, 'hidden1', 'hidden2'),
    packet(0, 'b', 'a'), packet(0, 'a', 'a')], positions);
  assert.equal(arrivalStateAt(rows.get('__broadcast'), 10).received, 1);
  assert.equal(arrivalStateAt(rows.get('__other'), 10).received, 1);
  assert.equal(arrivalStateAt(rows.get('a'), 10).received, 2);
  assert.equal(arrivalStateAt(rows.get('b'), 10).received, 0);
  assert.equal(buildArrivals([packet(0, 'missing', 'b')], new Map([['b', positions.get('b')]])).size, 0);
});

test('dense bursts keep every hit even when particles might be sampled', () => {
  const rows = buildArrivals(Array.from({ length: 5000 }, () => packet(0)), positions).get('b');
  const hit = arrivalStateAt(rows, rows[0][0]);
  assert.equal(hit.received, 5000);
  assert.equal(hit.burst, 5000);
  assert.equal(hit.recentHits, 5000);
});

test('impact returns to rest and stays bounded during a dense burst', () => {
  assert.equal(impactScale(Infinity), 1);
  assert.equal(impactScale(-.1), 1);
  assert.ok(impactScale(0, 1) > 1.5);
  for (let age = 0; age < IMPACT_SECONDS; age += .01) {
    const scale = impactScale(age, 100000);
    assert.ok(scale > .7 && scale <= 2.1);
  }
  assert.equal(impactScale(IMPACT_SECONDS, 100000), 1);
});
