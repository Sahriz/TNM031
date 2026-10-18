import React from 'react';
import { Check, X, Focus, FlaskConical, CircleHelp } from 'lucide-react';
import { RULES, clock, humanize } from './model.js';

function Empty({ title, children, icon: Icon = FlaskConical }) {
  return <div className="empty"><Icon size={28} /><h3>{title}</h3><p>{children}</p></div>;
}

export default function Evaluation({ report, onSeek }) {
  const evaluation = report.evaluation;
  if (!evaluation) return <section className="panel"><Empty title="No ground-truth labels" icon={FlaskConical}>Export this capture with its label file to compare detections with known attacks. Alert logs alone cannot be scored.</Empty></section>;
  const total = evaluation.overall;
  const anyAttacks = total.detected + total.missed > 0;
  return <>
    <div className="metrics evaluation-metrics">{[
      ['Precision', anyAttacks || total.false_positives ? `${(total.precision * 100).toFixed(1)}%` : '—', 'Detected attacks / (detected + false alarms)'],
      ['Recall', anyAttacks ? `${(total.recall * 100).toFixed(1)}%` : '—', `${total.detected} of ${total.detected + total.missed} attacks detected`],
      ['F0.5 score', anyAttacks ? total.f_half.toFixed(3) : '—', 'Greater weight on precision'],
      ['False positives', total.false_positives, `${evaluation.informational_ids.length} informational · ${evaluation.late_ids.length} late, excluded`],
    ].map(([label, value, detail]) => <div className="metric" key={label}><label>{label}</label><strong>{value}</strong><small>{detail}</small></div>)}</div>
    <section className="panel"><div className="panel-heading"><div><h2>Performance by rule</h2><p>Complete capture · current exported configuration</p></div><FlaskConical size={19} className="muted" /></div><div className="rule-results">{Object.entries(evaluation.rules).map(([rule, m]) => <div className="rule-result" key={rule}><div className="rule-result-top"><span>{RULES[rule]}</span><span className="mono">{m.detected} / {m.detected + m.missed}</span></div><div className="progress-track"><div style={{ width: `${m.recall * 100}%` }} /></div><div className="rule-result-bottom"><span>{m.missed} missed</span><span>{m.false_positives} false positives</span><span>F0.5 <b>{m.f_half.toFixed(2)}</b></span></div></div>)}</div></section>
    <section className="panel"><div className="panel-heading"><div><h2>Ground truth</h2><p>Attack scenarios and benign look-alikes from the label file</p></div><span className="count-tag">{report.events.length} events</span></div><div className="table-wrap"><table><thead><tr><th>Scenario</th><th>Rule</th><th>Time range</th><th>Label</th><th>Result</th><th /></tr></thead><tbody>{report.events.map(e => <tr key={e.id}><td className="capitalize">{humanize(e.subtype)}</td><td>{RULES[e.rule]}</td><td className="mono muted">{clock(e.start - report.start)} — {clock(e.end - report.start)}</td><td className="muted">{e.kind === 'attack' ? 'Attack' : 'Benign look-alike'}</td><td>{e.kind === 'attack' ? <span className={`result-pill ${evaluation.detected_event_ids.includes(e.id) ? 'detected' : 'missed'}`}>{evaluation.detected_event_ids.includes(e.id) ? <Check size={13} /> : <X size={13} />}{evaluation.detected_event_ids.includes(e.id) ? 'Detected' : 'Missed'}</span> : <span className="muted">Reference only</span>}</td><td><button className="icon-button" aria-label={`Jump to ${humanize(e.subtype)}`} onClick={() => onSeek(Math.min(report.duration, Math.max(0, e.start - report.start)))}><Focus size={16} /></button></td></tr>)}</tbody></table></div></section>
    <div className="note scoring-note"><CircleHelp size={18} /><div><strong>How to read these results</strong><p>Scoring uses medium and high alerts, with a {evaluation.slack}-second allowance after each attack. Low-severity and late alerts are listed separately and excluded from false positives. A detected event counts once, even if several alerts match. {report.source === 'Generated capture' ? 'These results describe simulated traffic; they do not establish real-world performance.' : ''}</p></div></div>
  </>;
}

