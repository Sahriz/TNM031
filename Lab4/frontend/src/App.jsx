import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDownToLine, CircleHelp, FileUp, LoaderCircle, Pause, Play, Repeat2, RotateCcw, SkipForward, X } from 'lucide-react';
import NetworkMap from './NetworkMap.jsx';
import TrafficChart from './TrafficChart.jsx';
import PortActivity from './PortActivity.jsx';
import Evaluation from './Evaluation.jsx';
import usePlayback from './usePlayback.js';
import { RANK, clock, download, formatNumber as n, networkStateAt, parseImport, validateReport } from './model.js';
import { PROTOCOL_COLORS, upperBound, networkLayout, threatJump } from './particles.js';

function ensurePackets(report) {
  if (!Array.isArray(report.packet_events)) throw new Error('This report has no packet stream. Export the capture again with dashboard.py. Alert-only logs cannot animate traffic.');
  return report;
}
const preciseClock = t => `${clock(t)}.${String(Math.floor(t % 1 * 1000)).padStart(3, '0')}`;

export default function App() {
  const [catalog, setCatalog] = useState([]), [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true), [error, setError] = useState('');
  const [page, setPage] = useState('overview'), [selected, setSelected] = useState(null);
  const [showLabels, setShowLabels] = useState(true), [help, setHelp] = useState(false);
  const [mode, setMode] = useState('all'), [stats, setStats] = useState({ drawn: 0, eligible: 0, unrouted: 0, sampled: false });
  const input = useRef(null), request = useRef(0), previousThreat = useRef(null);
  const playback = usePlayback(report?.duration || 0, page === 'overview' && !loading);
  const { time, playing, speed, loop } = playback;
  const layout = useMemo(() => report ? networkLayout(report) : null, [report]);
  const frame = useMemo(() => report ? networkStateAt(report, time) : null, [report, time]);
  const threats = frame?.alerts.filter(a => frame.active_ids.includes(a.id) && RANK[a.severity] >= 2) || [];
  const events = report?.packet_events || [];
  const observed = upperBound(events, time), rate = observed - upperBound(events, time - 1);
  const focusedHost = layout?.positions.get(selected);
  const unexported = report ? Math.max(0, report.packet_count - events.length) : 0;

  function acceptReport(value) {
    setReport(value); setSelected(null); setError(''); previousThreat.current = null;
    playback.update({ time: 0, speed: 1, playing: value.duration > 0 && !window.matchMedia('(prefers-reduced-motion: reduce)').matches });
  }
  async function loadCapture(entry) {
    const token = ++request.current; setLoading(true); playback.update({ playing: false });
    try {
      if (!entry || !/^[a-zA-Z0-9_.-]+\.json$/.test(entry.file)) throw new Error('Invalid capture entry. Refresh the exported reports.');
      const response = await fetch(`/reports/${entry.file}`);
      if (!response.ok) throw new Error('This capture could not be loaded. Refresh the exported reports.');
      const value = ensurePackets(validateReport(await response.json()));
      if (request.current === token) acceptReport(value);
    } catch (e) { if (request.current === token) setError(e.message); }
    finally { if (request.current === token) setLoading(false); }
  }
  useEffect(() => {
    let disposed = false;
    fetch('/reports/index.json').then(r => { if (!r.ok) throw new Error('No captures exported yet.'); return r.json(); })
      .then(entries => {
        if (disposed) return;
        if (!Array.isArray(entries) || !entries.length) throw new Error('No captures exported yet.');
        setCatalog(entries); loadCapture(entries[0]);
      }).catch(() => { if (!disposed) setLoading(false); });
    return () => { disposed = true; request.current++; };
  }, []);
  async function importCapture(event) {
    const file = event.target.files?.[0]; event.target.value = '';
    if (!file) return;
    const token = ++request.current; setLoading(true); playback.update({ playing: false });
    try {
      if (file.size > 50 * 1024 * 1024) throw new Error('Choose a report smaller than 50 MB. Export a shorter capture for smooth playback.');
      const value = ensurePackets(parseImport(await file.text(), file.name));
      if (request.current === token) acceptReport(value);
    } catch (e) { if (request.current === token) setError(e.message); }
    finally { if (request.current === token) setLoading(false); }
  }
  function nextThreat() {
    const next = threatJump(report, time, previousThreat.current);
    if (!next) return;
    previousThreat.current = next.alert.id;
    playback.update({ time: next.time, speed: next.speed, playing: true }); setSelected(null);
  }
  function seek(value) { previousThreat.current = null; playback.seek(value); }
  function updateStats(next) {
    setStats(current => Object.keys(next).every(k => current[k] === next[k]) ? current : next);
  }

  return <div className="flow-app">
    <header className="flow-topbar">
      <a className="brand" href="#" onClick={e => { e.preventDefault(); setPage('overview'); }}>netpulse <span>/ capture analysis</span></a>
      <nav className="flow-nav" aria-label="Main navigation">{[['overview', 'Overview'], ['evaluation', 'Evaluation']].map(([id, label]) => <button key={id} className={page === id ? 'selected' : ''} aria-current={page === id ? 'page' : undefined} onClick={() => setPage(id)}>{label}</button>)}</nav>
    </header>
    <main className="flow-main">
      <div className="flow-heading"><h1>{page === 'overview' ? 'Packet replay' : 'Detection evaluation'}</h1>
        <div className="heading-actions"><button className="button" onClick={() => input.current.click()}><FileUp size={14} />Load capture</button><button className="icon-button" aria-label="About packet playback" aria-expanded={help} onClick={() => setHelp(!help)}><CircleHelp size={17} /></button><input className="sr-only" type="file" ref={input} accept=".json" onChange={importCapture} aria-label="Import capture report" /></div>
      </div>
      {error && <div className="error-banner" role="alert">{error}<button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><X size={17} /></button></div>}
      {help && <div className="note"><CircleHelp size={18} /><div><strong>Reading the display</strong><p>All packets is the default: each exported packet gets one mark, including loops inside grouped addresses. Marks can overlap at screen resolution. Slight spatial separation makes bursts easier to see without changing their timing or count. Packets cross the map in under a second at 1×. Travel duration is illustrative and slows with playback speed. Landing packets bump the destination marker and add to its RX total. The larger number counts successive arrivals no more than 1.25 capture seconds apart. A quiet gap resets it; the RX total stays. Counts include all packets even in sampled mode and follow the replay cursor. Reduced-motion preferences disable impact animation.</p><p>Port activity counts TCP SYN probes over the preceding 10 capture seconds. Scans spread probes across ports or addresses; floods repeatedly hit a service. Packet color shows detector association, not ground-truth classification. Nodes highlight new detections for 3 capture seconds, then use neutral dashed outlines labeled retained. Retained alerts reflect detector memory, not confirmation of an ongoing attack. Next threat starts before detection and uses 0.25× for scans.</p><p>To load a PCAP or PCAPNG, first run <code>python dashboard.py path/to/capture.pcap</code>, then select it here or import the exported JSON. Sampled mode is optional for very large bursts; the drawn/eligible count stays visible.</p></div></div>}
      {loading ? <div className="loading" role="status"><LoaderCircle className="spin" size={22} /><p>Loading capture…</p></div> : !report ? <section className="panel setup-panel"><h2>Load a capture to see its traffic</h2><p>Export a PCAP or PCAPNG from the project folder, then refresh this page.</p><code>python dashboard.py data/test</code></section> : <>
        <div className="flow-source"><label htmlFor="capture-select">Capture</label><select id="capture-select" value={catalog.some(c => c.id === report.id) ? report.id : 'imported'} onChange={e => loadCapture(catalog.find(c => c.id === e.target.value))}>
          {!catalog.some(c => c.id === report.id) && <option value="imported">{report.name}</option>}{catalog.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select><span className="capture-kind">{report.source}</span><span className="capture-summary">{n(report.packet_count)} packets<span>/</span>{clock(report.duration)}</span></div>
        {page === 'overview' ? <>
          <div className="playback-controls" aria-label="Capture playback"><button className="play-button" aria-label={playing ? 'Pause playback' : 'Play capture'} disabled={!report.duration} onClick={playback.toggle}>{playing ? <Pause size={15} /> : <Play size={15} />}</button><button className="icon-button" aria-label="Restart capture" onClick={() => seek(0)}><RotateCcw size={15} /></button><span className="time-readout mono">{preciseClock(time)} <span>/ {clock(report.duration)}</span></span>
            <input className="timeline-slider" type="range" aria-label="Capture timeline" min="0" max={report.duration || 1} step="any" value={time} disabled={!report.duration} onChange={e => seek(Number(e.target.value))} />
            <select aria-label="Playback speed" value={speed} onChange={e => playback.update({ speed: Number(e.target.value) })}>{[.1, .25, .5, 1, 2, 4, 8, 16].map(s => <option key={s} value={s}>{s}×</option>)}</select><button className={`icon-button loop-button ${loop ? 'on' : ''}`} aria-label="Loop capture" aria-pressed={loop} onClick={() => playback.update({ loop: !loop })}><Repeat2 size={17} /></button><button className="button compact" disabled={!report.alerts.some(a => RANK[a.severity] >= 2)} onClick={nextThreat}><SkipForward size={14} />Next threat</button>
          </div>
          <section className="flow-stage" aria-label="Packet visualization">
            <div className="stage-toolbar"><div className={`stream-status ${playing ? 'playing' : ''}`}><i />{playing ? 'RUNNING' : 'PAUSED'}{speed < 1 && <span>slow motion</span>}</div><div className="stream-stats"><span><b>{n(observed)}</b> seen</span><span><b>{n(rate)}</b> packets/s</span><span title="Alerts retained by the detector; not a count of attacks currently in progress"><b>{threats.length}</b> detector alerts</span></div></div>
            <NetworkMap report={report} frame={frame} clock={playback.clock} selected={selected} onSelect={setSelected} layout={layout} mode={mode} onStats={updateStats} />
            <div className="map-scroll-hint">Scroll across the network to see all hosts →</div>
            {selected && <div className="focus-chip">Following {focusedHost?.name}<button className="icon-button" aria-label="Clear host focus" onClick={() => setSelected(null)}><X size={14} /></button></div>}
            <PortActivity report={report} time={time} selected={selected} layout={layout} />
            <div className="stage-bottom"><div className="legend">{Object.entries(PROTOCOL_COLORS).filter(([p]) => p !== 'other').map(([p, color]) => <span key={p}><i style={{ background: color }} />{p.toUpperCase()}</span>)}<span><i style={{ background: '#f7a05b' }} />Suspicious</span><span><i style={{ background: '#f16b60' }} />High threat</span><span title="Past detection still held by the detector"><i className="retained-key" />Retained alert</span></div>
              <div className="render-coverage"><label htmlFor="render-mode">Render</label><select id="render-mode" value={mode} onChange={e => setMode(e.target.value)}><option value="all">All packets</option><option value="sampled">Sampled</option></select><span className={stats.sampled ? 'sampling' : ''}><b>{n(stats.drawn)} / {n(stats.eligible)}</b> in flight</span>{stats.unrouted > 0 && <span>{n(stats.unrouted)} unroutable</span>}</div>
            </div>
          </section>
          <section className="flow-replay" aria-label="Full capture timeline"><div className="timeline-heading"><h2>Packet rate <span>full capture</span></h2><label className="toggle-label"><input type="checkbox" checked={showLabels} onChange={e => setShowLabels(e.target.checked)} />Labeled attacks</label></div><TrafficChart report={report} cursor={time} onSeek={seek} showLabels={showLabels} /></section>
        </> : <Evaluation report={report} onSeek={value => { playback.update({ time: value, playing: true }); setPage('overview'); }} />}
        <footer className="flow-footer"><span>{n(events.length)} / {n(report.packet_count)} packets exported{unexported > 0 ? ` · ${n(unexported)} have no usable endpoints` : ''} · geometry is illustrative · {report.detection_events ? 'detections at packet time' : `host status every ${report.interval}s`}</span><button onClick={() => download(JSON.stringify(report), `${report.id}.json`)}><ArrowDownToLine size={13} />Save report</button></footer>
      </>}
    </main>
  </div>;
}
