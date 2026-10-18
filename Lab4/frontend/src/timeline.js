export const CHART_HEIGHT = 100;
export const CHART_PAD = 28;
export const CHART_BOTTOM = CHART_HEIGHT - 19;

// Coordinates are in SVG space, after the browser's screen transform is inverted.
export function timelineTimeAt(x, y, width, duration) {
  const plotWidth = width - 2 * CHART_PAD;
  if (plotWidth <= 0 || ![x, y, width, duration].every(Number.isFinite)
    || duration <= 0 || x < CHART_PAD || x > width - CHART_PAD || y < 0 || y > CHART_BOTTOM) return null;
  return (x - CHART_PAD) / plotWidth * duration;
}
