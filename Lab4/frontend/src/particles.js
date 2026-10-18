// Packet rows: time, source, destination, protocol, severity, bytes, source port, destination port, TCP flags.
export const PROTOCOL_COLORS = { tcp: '#62d6ff', udp: '#b49aff', arp: '#81e6b7', other: '#9ba9c2' };
export const THREAT_COLORS = { low: '#9ba9c2', medium: '#f7a05b', high: '#f16b60' };
export const MAX_PARTICLES = 1200; // Only used when the user opts into sampled rendering.
export const PARTICLE_SPEED = 3; // Visual travel only; captured emission times stay intact.
export const TRAIL_SECONDS = 3 / PARTICLE_SPEED;
export const WORLD = { width: 1200, height: 570 };

export function upperBound(events, time) {
  let low = 0, high = events.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (events[middle][0] <= time) low = middle + 1;
    else high = middle;
  }
  return low;
}

export function packetWindow(events, time, mode = 'all', limit = MAX_PARTICLES) {
  const from = upperBound(events, time - TRAIL_SECONDS), to = upperBound(events, time);
  const stride = mode === 'sampled' ? Math.max(1, Math.ceil((to - from) / limit)) : 1;
  const indices = [];
  for (let i = from + ((stride - from % stride) % stride); i < to; i += stride) indices.push(i);
  return { indices, sampled: stride > 1, total: to - from, stride, from, to };
}

export function networkLayout(report) {
  const involved = new Set(report.alerts.flatMap(a => [a.actor, a.target]).filter(Boolean));
  const sorted = [...report.hosts].sort((a, b) => Number(b.known) - Number(a.known)
    || (!a.known ? Number(involved.has(b.id)) - Number(involved.has(a.id)) : 0)
    || a.id.localeCompare(b.id, undefined, { numeric: true }));
  const named = sorted.filter(h => h.known || involved.has(h.id));
  const visible = (named.length ? named : sorted).slice(0, 22);
  const services = visible.filter(h => ['web', 'dns', 'files', 'printer', 'gateway'].includes(h.name));
  const endpoints = visible.filter(h => !services.includes(h));
  const nodes = endpoints.map((host, i) => ({ ...host, side: 'left', x: 290,
    y: 50 + i * 470 / Math.max(1, endpoints.length - 1) }));
  services.forEach((host, i) => nodes.push({ ...host, side: 'right', x: 930,
    y: 75 + i * 420 / Math.max(1, services.length - 1) }));
  if (sorted.length > visible.length) nodes.push({ id: '__other', name: 'Other addresses', side: 'bottom',
    count: sorted.length - visible.length, x: 625, y: 487, first_seen: 0, special: true });
  if ((report.packet_events || []).some(p => p[2] === '__broadcast')) nodes.push({ id: '__broadcast',
    name: 'LAN broadcast', side: 'top', x: 625, y: 68, first_seen: 0, special: true });
  return { nodes, positions: new Map(nodes.map(n => [n.id, n])) };
}

function hash(text) {
  let result = 0;
  for (let i = 0; i < text.length; i++) result = (result * 31 + text.charCodeAt(i)) | 0;
  return result >>> 0;
}

export function routeKey(packet) {
  const servicePort = packet[8] & 16 ? packet[6] : packet[7];
  return `${packet[1]}|${packet[2]}|${servicePort || 0}`;
}

export function routeFor(packet, positions) {
  const source = positions.get(packet[1]) || positions.get('__other');
  const target = positions.get(packet[2]) || positions.get('__other');
  if (!source || !target) return null;
  // Retain traffic between grouped addresses and true self-addressed packets.
  if (source === target) return { source, target, loop: true,
    radius: 28 + hash(`${packet[1]}|${packet[2]}`) % 30, duration: 2.5 / PARTICLE_SPEED };
  const dx = target.x - source.x, dy = target.y - source.y, distance = Math.hypot(dx, dy);
  const servicePort = packet[8] & 16 ? packet[6] : packet[7];
  const portLane = servicePort ? (hash(String(servicePort)) % 111 - 55) : 0;
  const bend = Math.min(52, distance * .08) + portLane;
  return { source, target, nx: -dy / distance, ny: dx / distance,
    cx: (source.x + target.x) / 2 - dy / distance * bend,
    cy: (source.y + target.y) / 2 + dx / distance * bend,
    duration: Math.min(TRAIL_SECONDS, (2.2 + distance / 2500) / PARTICLE_SPEED) };
}

export function pointOnRoute(route, progress, index = 0) {
  const t = Math.min(1, Math.max(0, progress)), u = 1 - t;
  if (t === 0) return { x: route.source.x, y: route.source.y };
  if (t === 1) return { x: route.target.x, y: route.target.y };
  if (route.loop) return { x: route.source.x + Math.sin(t * Math.PI * 2) * route.radius,
    y: route.source.y - (1 - Math.cos(t * Math.PI * 2)) * route.radius };
  // Spatial separation only: emission times and packet counts are untouched.
  const spread = (((index * 17) % 23) - 11) * Math.sin(Math.PI * t);
  return { x: u * u * route.source.x + 2 * u * t * route.cx + t * t * route.target.x + spread * route.nx,
    y: u * u * route.source.y + 2 * u * t * route.cy + t * t * route.target.y + spread * route.ny };
}

export function matchesHost(packet, selected, positions) {
  return !selected || [packet[1], packet[2]].some(id => (positions.has(id) ? id : '__other') === selected);
}

export function probeActivity(events, time, selected, positions, seconds = 10) {
  const from = upperBound(events, time - seconds), to = upperBound(events, time);
  const ports = new Map(), targets = new Set(), sources = new Set();
  let probes = 0;
  for (let i = from; i < to; i++) {
    const p = events[i];
    if (p[3] !== 'tcp' || !(p[8] & 2) || p[8] & 16 || !matchesHost(p, selected, positions)) continue;
    probes++; targets.add(p[2]); sources.add(p[1]);
    const current = ports.get(p[7]) || { port: p[7], count: 0, severity: 'ok' };
    current.count++;
    if (p[4] === 'high' || p[4] === 'medium' && current.severity !== 'high') current.severity = p[4];
    ports.set(p[7], current);
  }
  return { probes, ports: [...ports.values()], targets: targets.size, sources: sources.size };
}

export function threatJump(report, time, previousId) {
  const alerts = report.alerts.filter(a => ['medium', 'high'].includes(a.severity));
  if (!alerts.length) return null;
  const previous = alerts.findIndex(a => a.id === previousId);
  const nearPrevious = previous >= 0 && Math.abs(time - (alerts[previous].ts - report.start)) < 5;
  const alert = nearPrevious ? alerts[(previous + 1) % alerts.length]
    : alerts.find(a => a.ts - report.start > time + .05) || alerts[0];
  // Replay the lead-in rather than seeking to the next whole-second snapshot.
  return { alert, time: Math.max(0, alert.ts - report.start - .6), speed: alert.rule === 'port_scan' ? .25 : 1 };
}
