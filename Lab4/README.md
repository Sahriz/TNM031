# Lab 4: rule-based intrusion detector

Detects port scans, TCP SYN floods and ARP spoofing in pcap files. It only reports; it never blocks traffic.

## Setup

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

## Usage

```
# 1. Mock captures with labels (reproducible from the seed)
.venv\Scripts\python -m mock.generate --out data/tune --count 8 --seed 100
.venv\Scripts\python -m mock.generate --out data/test --count 8 --seed 900

# 2. Run the detector on one capture
.venv\Scripts\python run.py data/test/test_00.pcap --out alerts.jsonl --status status.json

# 3. Tune thresholds on one set, score on the other
.venv\Scripts\python evaluate.py sweep data/tune --csv sweep.csv --write-config config.json
.venv\Scripts\python evaluate.py score data/test

# Traffic statistics, for comparing a mock capture with a real one
.venv\Scripts\python -m mock.stats data/tune/tune_00.pcap

# Tests
.venv\Scripts\python -m pytest
```

## Interactive dashboard

The local React dashboard replays captured packets as animated particles between
hosts. A Canvas renderer draws the traffic; SVG keeps host labels and the timeline readable.
No Kitsune download or live capture is needed. Node.js 22.12+ is required.

From this folder in PowerShell, run:

```powershell
.\start-dashboard.ps1
```

This exports the test captures if needed, installs frontend dependencies if missing,
and opens the local dashboard. Stop the server with Ctrl+C. If your PowerShell policy
blocks scripts, use these commands directly:

```powershell
.venv\Scripts\python dashboard.py data\test
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run dev
```

Open the Local address printed by the last command (normally http://127.0.0.1:5173).

- **Overview:** playback starts from the beginning at 1× and loops. Particles leave
  according to captured timestamps, with responses traveling back to their sender.
  Pause, restart, change speed, scrub the timeline, or choose **Next threat** to jump
  to the lead-in before a detection. Scan jumps use 0.25× so short bursts can be
  inspected; 0.1× is also available. Click a host to focus its traffic. Reduced-motion
  users start paused.
- TCP, UDP, and ARP have distinct particle colors. Amber and red particles indicate
  traffic associated with detector alerts. Nodes highlight a **new detection** for
  three capture seconds, then return to neutral with a dashed outline and a **retained**
  label while the detector holds the alert. These markers do not establish that an
  attack is still happening. Hover a marked host for the original detection time.
  The counter reports detector alerts, not a count of attacks currently in progress.
- Packets use cyan for TCP, violet for UDP, and mint for ARP, with soft bloom,
  tapered trails, and bright cores. Orange/red remain reserved for suspicious traffic. A landing bumps the destination marker
  and adds to its **RX** total. Arrivals no more than 1.25 capture seconds apart form
  a successive-arrival count; after a quiet gap it disappears, while RX keeps counting.
  Counts include all packets even in sampled mode and reconstruct correctly when
  seeking, restarting, or looping. These are visual arrivals after the illustrative
  travel time, not measurements of network delivery or latency. Reduced-motion
  preferences disable bumps and impact brackets; the counts remain available.
- **Packet rate:** click within the visible plot to seek. The plot fills the available
  width; its side margins and time labels do not accept seek clicks. The slider above
  the network also supports keyboard seeking.
- **TCP probes:** the strip below the network counts SYN attempts, distinct destination
  ports, and destinations over the preceding 10 capture seconds. A scan's breadth can
  be visible even when its packet volume is much lower than a flood's. Clicking a host
  also focuses these measurements. Port positions use the full 1–65,535 range.
- **Evaluation:** see per-rule metrics, detected/missed attacks, and benign labels.
  Scoring uses the existing evaluator, including its informational and late exclusions.
- **Load capture / Save report:** move exported JSON capture reports between browsers.
  Older reports should be exported again for port detail and immediate threat markers;
  alert-only logs cannot animate traffic. The startup script refreshes older bundled
  reports automatically.
  Imports remain inside the browser; the application does not upload them.

The packet counter and rate follow the **replay cursor**. Evaluation covers the
complete capture. Packet emission preserves subsecond timing. New detections and
escalations mark hosts at the triggering packet's timestamp; expiry is observed at
the next packet or snapshot boundary. Final alert evidence is never used to invent
earlier detector state. At 1×, particles cross the map in at most one second, three
times faster than the original animation, while capture emission times stay unchanged.
Particle travel time is illustrative, not measured latency,
and slows down along with playback. Slight spatial separation makes overlapping
packets easier to distinguish without changing their timestamps or counts.
**All packets** is the default, with one mark for every exported packet in flight.
Marks can still overlap at screen resolution. The renderer displays drawn/eligible
counts; optional **Sampled** mode caps candidates at 1,200 for very large bursts.
The footer reports export coverage, including packets with unusable endpoints.
The map is a logical view, not a physical topology. Named hosts come from the optional
label inventory. Additional addresses are grouped; traffic inside that group and
self-addressed packets appear as loops. Broadcasts travel to a LAN broadcast node. Faded hosts have not yet been
observed. Playback animates loaded captures; it does not capture current network traffic.

Reports are generated snapshots. After changing thresholds or captures, refresh them:

```powershell
.\start-dashboard.ps1 -RefreshReports
# Or refresh one capture (pcap and pcapng both work):
.venv\Scripts\python dashboard.py data\test\test_00.pcap
```

The exporter looks for an adjacent `.labels.json`, or accepts `--labels path/to/labels.json`.
Without labels, traffic and detections are shown and evaluation is unavailable.
To export longer captures with fewer detection snapshots, use `--interval 5` (maximum
20,000 replay frames); packet timestamps remain intact. Report imports are limited
to 50 MB. Raw pcap files must be exported
with Python before opening them in the dashboard.

```powershell
# Frontend checks and a static production build
npm.cmd --prefix frontend test
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run preview
```

The build includes the reports currently in `frontend/public/reports/`. Rebuild after
refreshing reports when using the production preview. Fonts are bundled locally;
the dashboard needs no external services after installation. Reports, dependencies,
and build output are ignored by Git. This is the portfolio visualization, separate
from the assessed detector. Three.js and real-traffic ingestion are not required.

## Layout

| Path | Purpose |
|---|---|
| `ids/packets.py` | Frame to header record (timestamp, addresses, ports, TCP flags, ARP sender) |
| `ids/state.py` | Per-host sliding windows, handshake tracking, IP-to-MAC table |
| `ids/rules.py` | The three rules and their settings |
| `ids/detector.py` | `handle(pkt)` pipeline and per-host status |
| `ids/alerts.py` | Alert record, rate-limiting, JSON lines output |
| `mock/` | Simulated LAN, background traffic, attacks, look-alikes, generator |
| `evaluate.py` | Scoring against labels and the threshold sweep |
| `config.json` | Thresholds, windows and allowlist (written by the sweep) |
| `dashboard.py` | Exports timed, directed packet events and frozen detection snapshots |
| `frontend/` | React playback, Canvas particles, SVG labels/charts, and frontend tests |
| `start-dashboard.ps1` | Starts the dashboard and prepares missing reports/dependencies |

## Rules

| Rule | Fires when | Subtypes | Severity |
|---|---|---|---|
| `port_scan` | One source has uncompleted connection attempts to `threshold` distinct (host, port) pairs within `window` seconds | `portscan`, `portsweep` | medium |
| `syn_flood` | One (host, port) receives `threshold` SYNs within `window` seconds and at least `min_incomplete_ratio` of the handshakes never complete | `single_source`, `many_sources` | high |
| `arp_spoof` | An IP address is claimed by a different MAC | `changed_address`, `flip_flop` | low, medium or high |

For `arp_spoof`, a change is low if the previous MAC has been silent for more than `stale_after` seconds (likely replaced hardware), medium if it is still active, and high when the same MAC takes the address again after the owner reclaimed it.

The rules run independently. A host's status is the most severe alert currently active for it, as actor or target. A repeated trigger extends the active alert instead of creating a new one.

## Scoring

An attack is detected if an alert of the same rule about the same host fires between its start and its end plus 10 seconds. The host is the source for scans and the target for floods and ARP spoofing. Every other alert is a false positive, with two exceptions that are listed separately and not scored: alerts about an attacked host after the attack ended, and low-severity alerts.

Precision is detected attacks over detected attacks plus false-positive alerts. Thresholds are chosen by F0.5.

## Limits

- Only TCP SYN scans are seen; UDP and ICMP scans are not.
- The capture must contain both directions, or every handshake looks uncompleted.
- Distributed scans stay under the per-source threshold and are missed.
- An ARP spoof of a host that has been silent longer than `stale_after` is reported as low severity only.
- Results on mock data say nothing certain about real traffic.
