import test from 'node:test';
import assert from 'node:assert/strict';
import { advancePlayback } from './usePlayback.js';
import { TRAIL_SECONDS } from './particles.js';

test('capture end keeps the final packet visible before looping', () => {
  const c = { time: 9.9, tail: 0, speed: 1, playing: true, loop: true };
  advancePlayback(c, .2, 10);
  assert.equal(c.time, 10);
  assert.ok(c.tail > 0 && c.tail < .2);
  advancePlayback(c, TRAIL_SECONDS, 10);
  assert.equal(c.time, 0);
  assert.equal(c.tail, 0);
  assert.equal(c.playing, true);
});

test('paused playback freezes and a non-looping capture drains before stopping', () => {
  const c = { time: 10, tail: 0, speed: 4, playing: false, loop: false };
  advancePlayback(c, 1, 10);
  assert.equal(c.tail, 0);
  c.playing = true;
  advancePlayback(c, TRAIL_SECONDS / (c.speed * 2), 10);
  assert.equal(c.playing, true);
  advancePlayback(c, TRAIL_SECONDS / (c.speed * 2), 10);
  assert.equal(c.playing, false);
  assert.equal(c.time, 10);
  assert.equal(c.tail, TRAIL_SECONDS);
});
