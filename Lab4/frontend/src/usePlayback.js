import { useEffect, useRef, useState } from 'react';
import { TRAIL_SECONDS } from './particles.js';

export function advancePlayback(c, elapsed, duration) {
  if (!c.playing || duration <= 0) return;
  let remaining = elapsed * c.speed;
  const step = Math.min(remaining, Math.max(0, duration - c.time));
  c.time += step; remaining -= step;
  if (c.time >= duration) {
    c.tail += remaining;
    // Give the last captured packets their complete path before looping or stopping.
    if (c.tail >= TRAIL_SECONDS) {
      if (c.loop) { c.time = 0; c.tail = 0; }
      else { c.tail = TRAIL_SECONDS; c.playing = false; }
    }
  }
}

export default function usePlayback(duration, enabled) {
  const clock = useRef({ time: 0, tail: 0, playing: false, speed: 1, loop: true });
  const [view, setView] = useState({ ...clock.current });
  function update(change) {
    if (change.time !== undefined) clock.current.tail = 0;
    Object.assign(clock.current, change);
    setView({ ...clock.current });
  }
  useEffect(() => {
    let handle, previous, lastPaint = 0;
    function tick(now) {
      const c = clock.current;
      if (previous !== undefined && c.playing && enabled && !document.hidden) {
        // Do not jump ahead after a suspended tab or a blocked animation frame.
        advancePlayback(c, Math.min((now - previous) / 1000, .1), duration);
      }
      previous = now;
      if (now - lastPaint >= 100) { setView({ ...c }); lastPaint = now; }
      handle = requestAnimationFrame(tick);
    }
    handle = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(handle);
  }, [duration, enabled]);
  return { ...view, clock, update,
    seek: time => update({ time: Math.max(0, Math.min(duration, time)) }),
    toggle: () => {
      const c = clock.current;
      const restart = !c.playing && c.time >= duration && (c.tail === 0 || c.tail >= TRAIL_SECONDS);
      update({ playing: !c.playing, ...(restart ? { time: 0 } : {}) });
    },
  };
}
