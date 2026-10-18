import React, { useMemo } from 'react';
import { probeActivity, PROTOCOL_COLORS, THREAT_COLORS } from './particles.js';
import { formatNumber as n } from './model.js';

export default function PortActivity({ report, time, selected, layout }) {
  const activity = useMemo(() => probeActivity(report.packet_events, time, selected, layout.positions), [report, time, selected, layout]);
  const hasPorts = report.packet_event_fields?.includes('destination_port');
  return <div className="port-instrument">
    <div className="port-instrument-heading"><span>TCP probes <small>last 10s{selected ? ' · focused host' : ''}</small></span>
      {hasPorts ? <span className="port-counts"><b>{n(activity.probes)}</b> probes <span>/</span> <b>{n(activity.ports.length)}</b> ports <span>/</span> <b>{n(activity.targets)}</b> {activity.targets === 1 ? 'destination' : 'destinations'}</span> : <small>Re-export this capture to include port detail.</small>}
    </div>
    <svg className="port-raster" viewBox="0 0 1100 28" preserveAspectRatio="none" role="img" aria-label={`${activity.probes} TCP SYN probes to ${activity.ports.length} distinct destination ports and ${activity.targets} destinations in the preceding ten seconds`}>
      <path d="M14 21H1086" stroke="#424941" strokeWidth=".7" />
      {[1, 16384, 32768, 49152, 65535].map(port => <path key={port} d={`M${14 + port / 65535 * 1072} 21v5`} stroke="#626c60" />)}
      {activity.ports.map(p => <path key={p.port} d={`M${14 + p.port / 65535 * 1072} 21v-${Math.min(19, 5 + Math.log2(p.count + 1) * 2)}`} stroke={THREAT_COLORS[p.severity] || PROTOCOL_COLORS.tcp} strokeWidth="1.5"><title>Port {p.port}: {p.count} probes</title></path>)}
    </svg>
    <div className="port-axis" aria-hidden="true">{[1, 16384, 32768, 49152, 65535].map(port => <span key={port}>{port.toLocaleString('en-US')}</span>)}</div>
  </div>;
}
