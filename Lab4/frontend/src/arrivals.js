import { routeFor, routeKey, upperBound } from './particles.js';

export const ARRIVAL_GAP = 1.25;
export const IMPACT_SECONDS = .45;

// Arrival times follow the illustrative particle journeys, not network latency.
// Index the full stream so sampling and dropped animation frames cannot lose hits.
export function buildArrivals(events, positions) {
  const nodes = new Map(), routes = new Map();
  events.forEach((packet, index) => {
    const key = routeKey(packet);
    if (!routes.has(key)) routes.set(key, routeFor(packet, positions));
    const route = routes.get(key);
    if (!route) return;
    if (!nodes.has(route.target.id)) nodes.set(route.target.id, []);
    nodes.get(route.target.id).push([packet[0] + route.duration, 0, index]);
  });
  for (const rows of nodes.values()) {
    // Different path lengths can make packets land out of emission order.
    rows.sort((a, b) => a[0] - b[0] || a[2] - b[2]);
    rows.forEach((row, i) => {
      row[1] = i > 0 && row[0] - rows[i - 1][0] <= ARRIVAL_GAP ? rows[i - 1][1] + 1 : 1;
    });
  }
  return nodes;
}

export function arrivalStateAt(rows = [], time) {
  const received = upperBound(rows, time);
  if (!received) return { received: 0, burst: 0, age: Infinity, packetIndex: -1, recentHits: 0 };
  const last = rows[received - 1], age = time - last[0];
  return { received, burst: age <= ARRIVAL_GAP ? last[1] : 0, age, packetIndex: last[2],
    recentHits: received - upperBound(rows, time - IMPACT_SECONDS) };
}

export function impactScale(age, recentHits = 1) {
  if (age < 0 || age >= IMPACT_SECONDS) return 1;
  const t = age / IMPACT_SECONDS, strength = Math.min(1.1, .6 + Math.log2(recentHits + 1) * .09);
  return 1 + strength * Math.exp(-6 * t) * Math.cos(10 * t);
}
