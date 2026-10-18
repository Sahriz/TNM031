import React, { useEffect, useMemo, useRef } from 'react';
import { RULES, RANK, clock as formatClock, detectionMarkers } from './model.js';
import { WORLD, PROTOCOL_COLORS, THREAT_COLORS, packetWindow, routeFor, routeKey, pointOnRoute, matchesHost } from './particles.js';
import { ARRIVAL_GAP, IMPACT_SECONDS, buildArrivals, arrivalStateAt, impactScale } from './arrivals.js';

const packetColor = packet => RANK[packet[4]] >= 2 ? THREAT_COLORS[packet[4]] : PROTOCOL_COLORS[packet[3]];
const countFormat = new Intl.NumberFormat('en-US');

export default function NetworkMap({ report, frame, clock, selected, onSelect, layout, mode, onStats }) {
  const canvas = useRef(null), bloom = useRef(null), world = useRef(null);
  const nodeElements = useRef(new Map());
  const arrivals = useMemo(() => buildArrivals(report.packet_events, layout.positions), [report, layout]);
  const markers = detectionMarkers(frame, report.start, frame.t);
  const current = useRef({ selected, mode, onStats });
  current.current = { selected, mode, onStats };

  useEffect(() => {
    const element = canvas.current, context = element.getContext('2d');
    const bloomElement = bloom.current, glow = bloomElement.getContext('2d');
    const events = report.packet_events, routes = new Map();
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let handle, width, height, scale, offsetX, offsetY, lastStats = -Infinity;
    function resize() {
      const rect = world.current.getBoundingClientRect(), dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width; height = rect.height;
      element.width = Math.round(width * dpr); element.height = Math.round(height * dpr);
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      // Bloom needs less resolution than the sharp foreground. Blur this layer once
      // in the compositor instead of applying a costly shadow to every packet.
      bloomElement.width = Math.max(1, Math.round(width / 2));
      bloomElement.height = Math.max(1, Math.round(height / 2));
      glow.setTransform(bloomElement.width / width, 0, 0, bloomElement.height / height, 0, 0);
      scale = Math.min(width / WORLD.width, height / WORLD.height);
      offsetX = (width - WORLD.width * scale) / 2; offsetY = (height - WORLD.height * scale) / 2;
    }
    const observer = new ResizeObserver(resize);
    observer.observe(world.current); resize();
    function draw(now) {
      const time = clock.current.time + clock.current.tail, options = current.current;
      const window = packetWindow(events, time, options.mode);
      context.clearRect(0, 0, width, height);
      glow.clearRect(0, 0, width, height);
      context.save(); context.translate(offsetX, offsetY); context.scale(scale, scale);
      glow.save(); glow.translate(offsetX, offsetY); glow.scale(scale, scale);
      const batches = new Map(), lanes = new Map(); let drawn = 0, eligible = 0, unrouted = 0;
      // Scan the entire active window even in sampled mode, so the coverage readout is exact.
      for (let index = window.from; index < window.to; index++) {
        const packet = events[index], key = routeKey(packet);
        if (!routes.has(key)) routes.set(key, routeFor(packet, layout.positions));
        const route = routes.get(key);
        if (!route) { unrouted++; continue; }
        const progress = (time - packet[0]) / route.duration;
        if (progress < 0 || progress >= 1) continue;
        eligible++;
        if (window.sampled && index % window.stride !== 0) continue;
        const focused = matchesHost(packet, options.selected, layout.positions);
        const color = packetColor(packet);
        const batchKey = `${color}|${focused}`;
        if (!batches.has(batchKey)) batches.set(batchKey, { color, focused, points: [] });
        const trail = [.045, .024, .009, 0].map(offset => pointOnRoute(route, Math.max(0, progress - offset), index));
        batches.get(batchKey).points.push(trail);
        const laneKey = `${route.source.id}|${route.target.id}`;
        if (focused && (!lanes.has(laneKey) || RANK[packet[4]] > RANK[lanes.get(laneKey).severity])) {
          lanes.set(laneKey, { route, color, severity: packet[4] });
        }
        drawn++;
      }
      // Faint paths take their tint from the traffic currently using them.
      context.globalAlpha = .13; context.lineWidth = .8;
      for (const { route, color } of lanes.values()) {
        if (route.loop) continue;
        context.strokeStyle = color; context.beginPath();
        context.moveTo(route.source.x, route.source.y);
        context.quadraticCurveTo(route.cx, route.cy, route.target.x, route.target.y);
        context.stroke();
      }
      context.lineCap = 'round'; glow.lineCap = 'round'; glow.lineJoin = 'round';
      for (const { color, focused, points } of [...batches.values()].sort((a, b) => Number(a.focused) - Number(b.focused))) {
        // Source-over blending bounds brightness in dense bursts instead of
        // accumulating thousands of additive glows into a white patch.
        glow.globalAlpha = focused ? .8 : .035;
        glow.strokeStyle = color; glow.lineWidth = 11; glow.beginPath();
        for (const trail of points) {
          glow.moveTo(trail[1].x, trail[1].y);
          glow.lineTo(trail[2].x, trail[2].y); glow.lineTo(trail[3].x, trail[3].y);
        }
        glow.stroke();
        context.strokeStyle = color;
        // A tapered tail, solid body, and chunky head give each packet weight.
        for (let segment = 0; segment < 3; segment++) {
          context.globalAlpha = [.16, .43, .92][segment] * (focused ? 1 : .08);
          context.lineWidth = [1.4, 2.4, 3.4][segment];
          context.beginPath();
          for (const trail of points) { context.moveTo(trail[segment].x, trail[segment].y); context.lineTo(trail[segment + 1].x, trail[segment + 1].y); }
          context.stroke();
        }
        context.globalAlpha = focused ? 1 : .08;
        context.fillStyle = color;
        for (const trail of points) { const head = trail[3]; context.fillRect(head.x - 2.1, head.y - 2.1, 4.2, 4.2); }
        context.globalAlpha = focused ? .92 : .05;
        context.fillStyle = '#eeffff';
        for (const trail of points) { const head = trail[3]; context.fillRect(head.x - .8, head.y - .8, 1.6, 1.6); }
      }
      for (const node of layout.nodes) {
        const elements = nodeElements.current.get(node.id);
        if (!elements) continue;
        const hit = arrivalStateAt(arrivals.get(node.id), time);
        const bump = reducedMotion.matches ? 1 : impactScale(hit.age, hit.recentHits);
        elements.marker.setAttribute('transform', `scale(${bump.toFixed(3)})`);
        const color = hit.received ? packetColor(events[hit.packetIndex]) : '#b4bdb5';
        const burstVisible = hit.burst > 1;
        const burstOpacity = burstVisible ? Math.min(1, (ARRIVAL_GAP - hit.age) / .3) : 0;
        const burstPop = reducedMotion.matches ? 1 : 1 + Math.max(0, bump - 1) * .25;
        elements.burst.setAttribute('transform', `scale(${burstPop.toFixed(3)})`);
        elements.burst.setAttribute('opacity', String(burstOpacity));
        elements.burst.setAttribute('aria-hidden', String(!burstVisible));
        elements.burst.setAttribute('fill', color);
        const burstText = `${countFormat.format(hit.burst)}×`;
        if (elements.count.textContent !== burstText) elements.count.textContent = burstText;
        const direction = node.side === 'right' ? -1 : 1;
        const countWidth = Math.max(34, burstText.length * 10 + 7);
        elements.total.setAttribute('x', String(direction * (burstVisible ? countWidth * burstPop + 16 : 0)));
        const totalText = hit.received ? `${countFormat.format(hit.received)} RX` : '';
        if (elements.total.textContent !== totalText) elements.total.textContent = totalText;
        elements.root.dataset.received = String(hit.received);
        elements.root.dataset.burst = String(hit.burst);
        // Small expanding impact brackets; host names stay still and readable.
        if (!reducedMotion.matches && hit.age < IMPACT_SECONDS) {
          const phase = hit.age / IMPACT_SECONDS, radius = 8 + 13 * phase;
          const focused = !options.selected || options.selected === node.id;
          glow.globalAlpha = (1 - phase) ** 2 * (focused ? .95 : .04);
          glow.strokeStyle = color; glow.lineWidth = 9;
          glow.strokeRect(node.x - 7, node.y - 7, 14, 14);
          context.globalAlpha = (1 - phase) ** 2 * (focused ? .65 : .08);
          context.strokeStyle = color; context.lineWidth = 1.5;
          context.beginPath();
          for (const [dx, dy] of [[-1, -1], [1, -1], [-1, 1], [1, 1]]) {
            const x = node.x + dx * radius, y = node.y + dy * radius;
            context.moveTo(x - dx * 4, y); context.lineTo(x, y); context.lineTo(x, y - dy * 4);
          }
          context.stroke();
        }
      }
      context.restore();
      glow.restore();
      element.dataset.particles = String(drawn); element.dataset.eligible = String(eligible);
      element.dataset.captureTime = time.toFixed(3); element.dataset.sampled = String(window.sampled);
      if (now - lastStats > 100) {
        options.onStats({ drawn, eligible, unrouted, sampled: window.sampled }); lastStats = now;
      }
      handle = requestAnimationFrame(draw);
    }
    handle = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(handle); observer.disconnect(); };
  }, [report, layout, clock, arrivals]);

  return <div className="particle-scroll"><div className="particle-world" ref={world}>
    <canvas ref={canvas} className="packet-canvas" role="img" aria-label="Captured packets moving between hosts; one mark per packet in all-packets mode" />
    <canvas ref={bloom} className="packet-bloom" aria-hidden="true" />
    <svg className="host-layer" viewBox={`0 0 ${WORLD.width} ${WORLD.height}`}>
      <text x="50" y="18" className="map-section">LOCAL / ENDPOINTS</text><text x="951" y="18" className="map-section">SERVICES</text>
      <text x="625" y="18" textAnchor="middle" className="map-section">RX total received</text>
      {[290, 930].map(x => <path key={x} d={`M${x - 6} 25h12M${x} 25v520M${x - 6} 545h12`} stroke="#30404a" strokeWidth=".6" fill="none" />)}
      {layout.nodes.map(node => {
        const alerts = markers.filter(a => [a.actor, a.target].some(id => id === node.id || node.id === '__other' && id && !layout.positions.has(id)));
        const fresh = alerts.filter(a => a.phase === 'new'), retained = alerts.filter(a => a.phase === 'retained');
        const severity = fresh.reduce((s, a) => RANK[a.severity] > RANK[s] ? a.severity : s, 'ok');
        const color = THREAT_COLORS[severity] || '#b4bdb5';
        const labels = entries => [...new Set(entries.map(a => RULES[a.rule]))].join(' / ');
        const phase = fresh.length ? 'new' : retained.length ? 'retained' : 'none';
        const observed = node.special || node.first_seen <= clock.current.time;
        const select = () => onSelect(selected === node.id ? null : node.id);
        const x = node.side === 'left' ? -18 : node.side === 'right' ? 18 : 0;
        const y = node.special ? 21 : -2, anchor = node.side === 'left' ? 'end' : node.side === 'right' ? 'start' : 'middle';
        const badgeDirection = node.side === 'right' ? -1 : 1;
        return <g key={node.id} transform={`translate(${node.x},${node.y})`} className="flow-host"
          ref={element => {
            if (!element) { nodeElements.current.delete(node.id); return; }
            nodeElements.current.set(node.id, { root: element, marker: element.querySelector('.host-marker'),
              burst: element.querySelector('.arrival-burst'), count: element.querySelector('.burst-count'),
              total: element.querySelector('.arrival-total') });
          }}
          opacity={!observed ? .27 : selected && selected !== node.id ? .48 : 1} role="button" tabIndex="0"
          data-alert-phase={phase} aria-label={`Focus ${node.name}${alerts.length ? `, ${labels(alerts)}, ${phase === 'new' ? 'new detection' : 'retained alert'}` : ''}`}
          aria-pressed={selected === node.id} onClick={select} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); } }}>
          {alerts.length > 0 && <title>{alerts.map(a => `${RULES[a.rule]}: detected at ${formatClock(a.ts - report.start)}. ${a.phase === 'new' ? 'New detection (highlighted for 3 capture seconds).' : 'Retained by the detector; this does not confirm an ongoing attack.'}`).join('\n')}</title>}
          <rect x={node.side === 'left' ? -225 : -9} y="-15" width={node.special ? 18 : 234} height="31" fill="transparent" />
          <g className="host-marker">
          <rect className="host-target" x="-4.5" y="-4.5" width="9" height="9" fill={color} />
          </g>
          {selected === node.id && <path d="M-10-5v-5h5M5-10h5v5M10 5v5H5M-5 10h-5V5" stroke="#ebeee6" fill="none" />}
          {alerts.length > 0 && <rect x="-9" y="-9" width="18" height="18" fill="none" stroke={fresh.length ? color : '#737373'} strokeWidth="1" strokeDasharray={fresh.length ? undefined : '3 3'} />}
          <g className="arrival-badge" transform={`translate(${badgeDirection * 23},4)`} pointerEvents="none">
            <g className="arrival-burst" opacity="0"><text className="burst-count" textAnchor={badgeDirection === 1 ? 'start' : 'end'} /></g>
            <text className="arrival-total" textAnchor={badgeDirection === 1 ? 'start' : 'end'} />
          </g>
          <text x={x} y={y} textAnchor={anchor} className="flow-host-name">{node.name}</text>
          <text x={x} y={y + 13} textAnchor={anchor} className="flow-host-ip">{node.count ? `${node.count} addresses · internal traffic ↺` : node.special ? 'Broadcast destination' : node.name !== node.id ? node.id : ''}</text>
          {fresh.length > 0 && <text x={node.side === 'left' ? 16 : -16} y="-13" textAnchor={node.side === 'left' ? 'start' : 'end'} className="flow-threat-label" fill={color}>{labels(fresh)} · new</text>}
          {retained.length > 0 && <text x={node.side === 'left' ? 16 : -16} y={fresh.length ? -26 : -13} textAnchor={node.side === 'left' ? 'start' : 'end'} className="flow-threat-label" fill="#858585">{labels(retained)} · retained</text>}
        </g>;
      })}
    </svg>
  </div></div>;
}
