import React, { useLayoutEffect, useRef, useState } from 'react';
import { clock } from './model.js';
import { CHART_HEIGHT as height, CHART_PAD as pad, CHART_BOTTOM, timelineTimeAt } from './timeline.js';

export default function TrafficChart({ report, cursor, onSeek, showLabels }) {
  const chart = useRef(null), [width, setWidth] = useState(1100);
  useLayoutEffect(() => {
    const element = chart.current;
    const resize = () => setWidth(Math.max(2 * pad + 1, element.getBoundingClientRect().width));
    const observer = new ResizeObserver(resize);
    observer.observe(element); resize();
    return () => observer.disconnect();
  }, []);
  const span = report.duration || 1;
  const data = report.frames.map((f, i) => ({ t: f.t, rate: f.traffic.packets / Math.max(.001, i ? f.t - report.frames[i - 1].t : report.interval) }));
  const max = Math.max(1, ...data.map(p => p.rate));
  const x = t => pad + t / span * (width - 2 * pad);
  const y = rate => height - 19 - rate / max * (height - 34);
  const bars = data.map(p => `M${x(p.t).toFixed(2)},${height - 19}V${y(p.rate).toFixed(2)}`).join(' ');
  function seek(event) {
    const matrix = chart.current.getScreenCTM();
    if (!matrix) return;
    const point = chart.current.createSVGPoint();
    point.x = event.clientX; point.y = event.clientY;
    const local = point.matrixTransform(matrix.inverse());
    const time = timelineTimeAt(local.x, local.y, width, report.duration);
    if (time !== null) onSeek(time);
  }
  return <svg ref={chart} className="traffic-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Packet rate over the full capture. Click inside the plot or use the capture timeline slider to move through time.">
    <g className="traffic-plot" onClick={seek}>
    <rect className="timeline-hit-area" x={pad} y="0" width={width - 2 * pad} height={CHART_BOTTOM} fill="transparent" />
    {[0, .5, 1].map(v => <g key={v}><line x1={pad} x2={width - pad} y1={y(max * v)} y2={y(max * v)} stroke="#2d3942" strokeWidth=".6" /><text x={width - pad} y={y(max * v) - 4} textAnchor="end" className="chart-label">{Math.round(max * v)} p/s</text></g>)}
    {showLabels && report.events.filter(e => e.kind === 'attack').map(e => <rect key={e.id} x={x(e.start - report.start)} y="8" width={Math.max(3, (e.end - e.start) / span * (width - 2 * pad))} height={height - 27} fill="#e9b46e" opacity=".10"><title>{e.subtype}: {clock(e.start - report.start)}–{clock(e.end - report.start)}</title></rect>)}
    <path d={bars} fill="none" stroke="#63bdd9" strokeWidth="1.3" vectorEffect="non-scaling-stroke" />
    {report.alerts.map(a => <circle key={a.id} cx={x(a.ts - report.start)} cy="7" r="3" fill={a.severity === 'high' ? '#f17c87' : a.severity === 'medium' ? '#edbd70' : '#78aef0'}><title>{a.rule} at {clock(a.ts - report.start)}</title></circle>)}
    <line x1={x(cursor)} x2={x(cursor)} y1="0" y2={height - 19} stroke="#e4f3ed" strokeWidth="1" /><circle cx={x(cursor)} cy="4" r="3" fill="#e4f3ed" />
    </g>
    {[0, .25, .5, .75, 1].map(v => <text key={v} x={x(span * v)} y={height - 1} textAnchor="middle" className="chart-label">{clock(span * v)}</text>)}
  </svg>;
}
