# TNM031 Lab 4 — IDS project: reference tools and mock-data resources

Context: rule-based intrusion detector for port scans, SYN floods and ARP spoofing. After the meeting with Pierangelo (late Sept 2026): focus on mock data; look at what existing tools/services promise and use that as the baseline; the visualization is not part of the course assessment (built later, portfolio extra). Local prototype: netpulse_mock.py (stdlib Python; mock generator + 3 detectors + evaluation) — Jonatan will NOT send or mention it to the examiner. Language: Python + Scapy.

## Decisions (Oct 2026)
- Structure: independent hand-written rules (one per attack) run on every host's recent traffic in sliding time windows; each host's status = most severe alert currently active for it. A hand-built decision tree was considered and dropped: it returns one verdict per host and hides simultaneous attacks, and established systems evaluate rules independently.
- Packet reading: write the detector as one function that takes a single packet (`handle(pkt)` → decode headers → update per-host counters → run rules → alerts). Source is swappable: Scapy `PcapReader` on pcap/pcapng files now (mock data; later Wireshark/tcpdump recordings — Wireshark saves pcapng by default, Scapy reads both); later stage live capture with Scapy `sniff(iface, prn=handle, store=False)` via libpcap (Npcap on Windows), own machine/network only. Decode headers only (timestamp, IPs, ports, TCP flags, ARP sender IP+MAC) — all three attacks are visible in headers, so encryption doesn't hide them.
- Mock data: Python + Scapy builds full Ethernet frames, writes pcap + a label file (attack start/end). Background: simulated hosts, complete TCP handshakes, DNS lookups, ARP exchanges, random timing. Validation: (1) leave checksums/lengths unset so Scapy computes them; keep seq/ack numbers consistent; (2) open every file in Wireshark (Expert Information, Statistics → Conversations); (3) compare background rates/protocol mix with a short private capture of normal traffic from own machine (statistics only); (4) compare attacks with real attacks in the Kitsune captures (rate, distinct ports/sec, SYN/SYN-ACK/RST mix); (5) include look-alikes — backup job touching many ports (scan), burst of real connections that complete (flood), legitimate MAC change e.g. replaced NIC / router failover (ARP) — plus hard attacks (slow scans, distributed scans); (6) tune thresholds on one set of generated files, evaluate on fresh files with different seeds/intensities; (7) state the limit: mock data can't prove real-world performance (Kitsune check covers that).
- Evaluation: detection rate + false positives against labels; threshold sweep; false positives weighted more heavily than misses when choosing thresholds (F0.5: precision counts twice as much as recall). Optional extension: fixed scan threshold vs Threshold Random Walk.
- Email sourcing: only the services/tools whose methods we compare to, one source per claim (Snort 3 port scan, Suricata thresholding, arpwatch, GuardDuty) + Kitsune (actually used). No prototype mention. The academic references below are for the later report, not the email.
- Email voice: first person, active voice, plain paragraphs, American spelling (matches Jonatan's own first email: "visualization", "analyze").
- Prototype gaps vs the plan: no per-host status; SYN rule counts SYNs only (no completion check); mock data in memory, not pcap.

## Phases
1. Mock data → pcap files + label file (Scapy), validated as above.
2. Detector: `handle(pkt)` pipeline, per-host windows, three independent rules (SYN rule with completion check), per-host status, JSON alerts.
3. Evaluation: detection rate, false positives (F0.5), threshold sweep; optional fixed threshold vs TRW.
4. Real-traffic check on Kitsune captures; later, recordings from own machine; eventually live capture on own network.
5. Portfolio extra (not graded): three.js visualization reading alerts.jsonl; optional C++ port.

## Final email to Pierangelo (draft v3, Oct 2026 — toned-down voice)
Subject: Lab 4 project plan

Hi Pierangelo,

Thanks for taking the time to talk about my Lab 4 idea. I've taken your advice and focused on mock data, and I've looked at how existing tools deal with the same attacks so I have something to compare against. Here's the plan.

The project is a network intrusion detection system for three attacks: port scans, TCP SYN floods and ARP spoofing. It only detects and reports, and doesn't block any traffic.

Instead of matching packets against known attack signatures, the system keeps a summary of each host's recent traffic and checks it against rules I write for each attack. The rules run independently, so a host can trigger more than one, and each host's status is based on its most severe alert. I'm writing the rules by hand rather than training a model, so every alert can be traced back to the rule that caused it.

- Port scan: one source contacting many different ports or hosts in a short time. Snort 3 detects scans in a similar way [1].
- SYN flood: lots of connection attempts to one host where the TCP handshake never completes. Suricata can catch the high rate with a threshold rule [2], and checking whether handshakes complete also helps separate a flood from a normal burst of connections.
- ARP spoofing: an IP address whose MAC address suddenly changes, which is what arpwatch looks for [3].

The detector reads pcap files with Scapy (Python) and pulls out the header fields the rules need: timestamp, IP addresses, ports, TCP flags, and for ARP the sender's IP and MAC address. Each packet updates the counters for the hosts involved, and the rules are checked after every update. Since pcap is the standard capture format, the same code can later run on traffic recorded with Wireshark, or on live traffic from my own network through Npcap, without changing the detection part.

The mock data comes from a Python script (also using Scapy) that writes pcap files, plus a label file saying when each attack happens. The background is normal traffic between a set of simulated hosts, with complete TCP handshakes, DNS lookups and ARP requests at random intervals, and the attacks are added at known times. I'll open the files in Wireshark to make sure everything decodes properly. I'll also compare the background with a capture of normal traffic from my own machine, and the attacks with the real ones in the labeled Kitsune dataset [4]. The data will include normal traffic that looks like an attack, such as a backup job that connects to a lot of ports, so that false positives actually get tested. I'll tune the thresholds on one set of generated files and test on a separate set.

Each alert is saved as JSON with the rule, severity, attacker, target and the evidence behind it, similar to how AWS GuardDuty reports its findings [5].

For the evaluation I'll look at detection rate and false positives against the labels, and how both change with the thresholds. I'll weigh false positives more heavily than missed attacks when picking thresholds, for example using an F0.5 score. If there's time, I'd also like to compare the fixed port scan threshold with a statistical method (Threshold Random Walk).

I'm still planning to build the visualization on top of this later, but that's separate from the course and not part of what I'm handing in.

Does this sound like a reasonable scope, or would you change anything?

Best regards,
Jonatan

References
[1] Snort 3 Inspector Reference, Port Scan Inspector: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/snort3-inspectors/snort-3-inspector-reference/port-scan-inspector.html
[2] Suricata documentation, Thresholding Keywords: https://docs.suricata.io/en/latest/rules/thresholding.html
[3] arpwatch manual page: https://man.archlinux.org/man/extra/arpwatch/arpwatch.8.en
[4] Y. Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", NDSS 2018. Dataset: https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset
[5] AWS GuardDuty User Guide, EC2 finding types: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html

## Approach framing (tool-agnostic, for the report)
- NIST SP 800-94 §2.3 lists three detection methodologies: signature-based (match known attack patterns; very effective on known threats, largely blind to unknown ones), anomaly-based (profile of normal, flag significant deviations; catches unknown threats but prone to false positives and hard to profile), stateful protocol analysis (compare against expected protocol behaviour; catches multi-step misuse, very resource-intensive, misses attacks that stay within normal protocol behaviour).
- NIST SP 800-94 §6 "Network Behavior Analysis": examines network traffic to identify threats that generate unusual traffic flows (e.g. DDoS, certain malware such as worms/backdoors, policy violations). Closest label for this project.
- Anomaly detection originates with Denning 1987: "security violations can be detected by monitoring a system's audit records for abnormal patterns of system usage."
- This project = hand-written behavioural + stateful rules over per-host traffic summaries in short time windows. Port scan = threshold rule on behaviour. SYN flood = stateful (handshakes that never complete) + threshold. ARP spoof = stateful (IP→MAC binding changes).
- Learned models (e.g. a trained decision tree) = supervised ML; trained on self-generated mock data they risk learning generator quirks.
- Refs: K. Scarfone, P. Mell, "Guide to Intrusion Detection and Prevention Systems (IDPS)," NIST SP 800-94, Feb 2007, https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-94.pdf · D. E. Denning, "An Intrusion-Detection Model," IEEE Trans. Software Engineering SE-13(2), 1987, pp. 222–232.

## Academic references (verified Oct 2026, for the report)
1. M. Roesch, "Snort — Lightweight Intrusion Detection for Networks," Proc. USENIX LISA '99, 1999. https://www.usenix.org/legacy/event/lisa99/full_papers/roesch/roesch.pdf
2. V. Paxson, "Bro: A System for Detecting Network Intruders in Real-Time," Proc. 7th USENIX Security Symposium, 1998. https://www.icir.org/vern/papers/bro-CN99.pdf
3. J. Jung, V. Paxson, A. Berger, H. Balakrishnan, "Fast Portscan Detection Using Sequential Hypothesis Testing," IEEE S&P, 2004 — TRW. https://people.csail.mit.edu/awberger/papers/fastPortscanDetectionUsingSequentialHypothesisTesting_JungPaxsonBergerBalakrishnan_2004.pdf
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, 2007. https://www.rfc-editor.org/rfc/rfc4987
5. H. Wang, D. Zhang, K. G. Shin, "Change-Point Monitoring for the Detection of DoS Attacks," IEEE TDSC, vol. 1, 2004. https://ieeexplore.ieee.org/document/1388279/
6. C. Abad, R. Bonilla, "An Analysis on the Schemes for Detecting and Preventing ARP Cache Poisoning Attacks," ICDCS Workshops, 2007.
7. R. Sommer, V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," IEEE S&P, 2010.
8. S. Axelsson, "The Base-Rate Fallacy and the Difficulty of Intrusion Detection," ACM TISSEC 3(3), 2000.
9. C. G. Cordero et al. (incl. S. Nadjm-Tehrani, LiU), "On Generating Network Traffic Datasets with Synthetic Attacks for Intrusion Detection," ACM TOPS, 2021. https://arxiv.org/abs/1905.00304
10. Y. Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection," NDSS 2018. https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03A-3_Mirsky_paper.pdf

## What existing tools promise, per attack (prior art)

### Port scans
- **Snort 3 `port_scan` inspector** — portscan / portsweep / decoy / distributed; TCP/UDP/ICMP/IP; thresholds: scans, rejects, ports, nets; `ignore_scanners`. https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/snort3-inspectors/snort-3-inspector-reference/port-scan-inspector.html
- **Zeek `scan.zeek` / simple-scan** — failed connection attempts per source; Address/Port/Random Scan; 25 unique failed host+port combos (250 internal), 15-minute window; weak on slow and distributed scans. https://docs.zeek.org/en/v5.2.2/scripts/policy/misc/scan.zeek.html · https://zeek.org/2026/09/how-attackers-learn-your-network-before-they-attack-it/
- **AWS GuardDuty** — `Recon:EC2/Portscan` (actor) vs `Recon:EC2/PortProbeUnprotectedPort` (target); from VPC flow logs. https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html

### SYN floods
- **Suricata** — `threshold` / `detection_filter` (N matches within T seconds, by source or destination). https://docs.suricata.io/en/latest/rules/thresholding.html
- **AWS GuardDuty** — `Backdoor:EC2/DenialOfService.Tcp`, High severity.
- **Mitigation** — backlog, recycling half-open connections, SYN cookies; Cloudflare proxies the handshake. https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/

### ARP spoofing
- **Snort 3 `arp_spoof` inspector** — unicast ARP requests, Ethernet/ARP mismatches, cache overwrite (needs `hosts[]`). https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/snort3-inspectors/snort-3-inspector-reference/arp-spoof-inspector.html
- **arpwatch** — new station, changed ethernet address, flip flop. https://man.archlinux.org/man/extra/arpwatch/arpwatch.8.en

### Managed platforms
- **Google Cloud IDS** — Palo Alto signatures; detection-only. https://docs.cloud.google.com/intrusion-detection-system/docs/overview
- **Azure Firewall Premium IDPS** — 67,000+ signatures; off/alert/alert-and-deny; High/Medium/Low. https://learn.microsoft.com/en-us/azure/firewall/premium-features
- **NDR vendors** (Darktrace, Vectra AI, ExtraHop) — ML baselining, alert-noise reduction, packet forensics (vendor claims). https://tech-insider.org/darktrace-vs-vectra-ai-vs-extrahop-2026/

## Baseline feature list for the lab (sized down)
1. Detect each attack with named subtypes. 2. Configurable threshold + time window per rule. 3. Severity per alert. 4. Actor vs target. 5. Allowlist + alert rate-limiting. 6. JSON alerts with rule and evidence. 7. Detection-only. 8. Evaluation: misses vs false alarms, threshold sweep, documented weak spots.

Non-goals: signature libraries, ML, TLS decryption, high throughput, threat-intel feeds, blocking.

## Optional empirical baseline comparison
If practical, run an established engine on the same mock pcaps: Snort 3 `port_scan` / Zeek (scans), a Suricata/Snort threshold rule (SYN floods), Snort 3 `arp_spoof` (ARP). All read pcaps with `-r`; on Windows use WSL2 or Docker.

## Backend tech stack options (decided: Python + Scapy)
| Stack | Libraries | Advantages | Drawbacks |
|---|---|---|---|
| Python (chosen) | Scapy, dpkt | Fastest to build; Scapy generates and parses pcaps | Slow at high packet rates (irrelevant offline) |
| C++ | libpcap/Npcap, PcapPlusPlus | Performance; same language as Snort 3/Zeek | More code per feature |
| C# / .NET | SharpPcap + Packet.Net; SignalR | One ecosystem incl. web streaming; fits .NET track | Few security-research examples |
| Go | gopacket | Concurrency, single binary | New language |
| Existing engine | Zeek scripts / Suricata rules | Backend is the cited system | Reads as configuration |

## Mock data resources
- **Scapy** — build frames, `wrpcap()` to file. https://thepacketgeek.com/scapy/writing-packets/
- **ID2T** — injects synthetic attacks into existing pcaps with labels. https://github.com/tklab-tud/ID2T
- **Kitsune dataset** — raw pcaps (benign then attack) + per-packet labels; OS Scan (nmap), SYN DoS (hping3), ARP MitM (Ettercap). https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset
- **tcpreplay** — replay pcaps onto an interface. https://tcpreplay.appneta.com/
