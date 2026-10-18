import test from 'node:test';
import assert from 'node:assert/strict';
import { CHART_PAD, CHART_BOTTOM, timelineTimeAt } from './timeline.js';

test('timeline positions follow the visible plot at desktop and mobile widths', () => {
  for (const width of [320, 1100, 2000]) {
    for (const fraction of [0, .25, .5, .75, 1]) {
      const x = CHART_PAD + (width - 2 * CHART_PAD) * fraction;
      assert.equal(timelineTimeAt(x, 40, width, 400), 400 * fraction);
    }
  }
});

test('margins and time labels cannot seek to the beginning or end accidentally', () => {
  for (const width of [320, 2000]) {
    for (const [x, y] of [[0, 40], [CHART_PAD - .01, 40], [width - CHART_PAD + .01, 40],
      [width, 40], [width / 2, -1], [width / 2, CHART_BOTTOM + .01], [width / 2, 99]]) {
      assert.equal(timelineTimeAt(x, y, width, 400), null);
    }
  }
  assert.equal(timelineTimeAt(50, 20, 320, 0), null);
  assert.equal(timelineTimeAt(NaN, 20, 320, 400), null);
});

test('short captures use their actual duration across the entire plot', () => {
  assert.equal(timelineTimeAt(160, 40, 320, .5), .25);
});
