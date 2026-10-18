# Questions worth a second look

The answers are based on *Security Vulnerabilities and Countermeasures in TCP/IP Layers* (Mugala, 2014), but the paper doesn't cover everything the assignments ask. Below are the answers that depend on general course knowledge, on an assumption, or on how the teacher reads the question.

## Assignment 1

### Q4 and Q5: IP header size
The paper never mentions header sizes. I assumed **IPv4** (min 20 B, max 60 B), because Q5's bit pattern only makes sense for IPv4 (version = 0100). An IPv6 header is a fixed 40 bytes, so if the teacher meant both versions, add a line about that.

### Q11, Q12, Q18: SYN/ACK and SYN/FIN scans, firewall rules
None of these are in the paper. The answers follow the usual textbook explanation (Panko-style):
- SYN/ACK gets past simple filters
- the target answers with RST
- block unsolicited SYN/ACKs and outgoing RSTs

For Q12, real OS behaviour varies. "Some reply RST, some ignore it, and the difference helps fingerprinting" is a safe general answer, but the course slides may name specific responses.

### Q16: attacker must use their real IP
I wrote that scans need the replies, so the attacker can't spoof the source. That holds in general, but decoy scans (e.g. nmap `-D`) mix in spoofed addresses. It's fine at this level, but it's a simplification.

### Q19: number of packets
There are three ways to count this:
- **Which ports count?** 0–1023 gives 1024 ports, so 102 400 packets. If port 0 is left out (1–1023), it's 102 300.
- **TCP only, or TCP + UDP?** Both doubles the number to 204 800.
- **Packets per port.** I counted one probe (SYN) per port. If the attacker also sends a RST to tear down each half-open connection, that's 2 per open port, but the number of open ports isn't given, so one probe per port is the reasonable reading.

Check which convention the lectures used.

### Q23 and Q24: SYN flood countermeasures, SYN cookies
The paper only mentions the **firewall acting as a proxy**. SYN cookies, shorter timeouts, a bigger backlog and ingress filtering are all correct, but they come from outside the paper. If the teacher wants answers strictly from the paper, Q23 could be cut down to the proxy point. Q24 can't be answered from the paper at all.

### Q25: Smurf attack
The paper's description leaves out the key detail that the **source IP is spoofed to be the victim's**. Without it, the replies would go back to the attacker. I added it because the attack doesn't make sense otherwise, so this answer deliberately goes beyond the paper.

### Q27 and Q28: attacks with or without IP spoofing
These lists are judgment calls. Some attacks could go in either list:
- **Ping of death / teardrop** can be sent with or without a spoofed source, so I left them out of both lists.
- **ARP spoofing / gratuitous ARP** fakes IP-to-MAC bindings, not the IP source address of a packet. I left it out of Q27.
- **DHCP starvation** spoofs MAC addresses, not IPs, so I put it in Q28 with that caveat.
- **Session hijacking** is in Q27 as *TCP blind spoofing*. Hijacking by sniffing on the same LAN doesn't strictly need spoofing.

The teacher may expect different examples, so compare with the lecture list if there is one.

## Assignment 2

The paper barely covers firewalls. It only mentions WAFs, a firewall acting as a SYN proxy, and TCP wrappers. **All of Assignment 2 is based on general course knowledge**, so compare with the firewall lecture/chapter.

### Numbering
The original sheet has two questions numbered **5**. I numbered the second one (proxy count) **6**. Check whether the teacher wants the original numbering kept.

### Q3: stateful firewalls and UDP/ICMP
I wrote "Yes, sort of". The textbook answer is just **yes**: the firewall tracks the request/reply pair as a pseudo-connection with a timeout. Consider changing it to a plain "Yes" so it doesn't read as unsure.

### Q6: number of proxy programs
Answered **four** (one per application). Some might argue a single multi-protocol proxy *server* can handle several applications, but the question asks about *programs*, and the standard answer is one per application.

### Q9: the LiU ACL ("tricky question")
This one rests on assumptions, so it's the one most worth checking.

1. **Stateless vs. stateful.** My main argument is that return traffic (e.g. SYN/ACK from an external server) has no allow rule and gets dropped, so outbound connections don't work. That's only true if this is a **stateless packet filter**. If the teacher assumes a stateful firewall, return traffic is allowed automatically and that argument falls away. The ACL looks stateless (no direction or state keywords, per-host rules), so I went with that, but the answer says this assumption out loud.
2. **Spoofing.** The rules match only on source IP, not on interface, so an outsider can fake `130.236.136.96` and reach internal hosts. This holds either way and is probably the "tricky" part the teacher means. If you have to cut the answer down, keep this point.
3. **Only TCP.** UDP and ICMP outbound (DNS, ping) are dropped. That breaks "allow all outbound connections" if *connections* includes UDP traffic. A teacher could argue that only TCP has real connections, so this is the weakest of the three points.
4. **The mail server's own outbound traffic.** Rule 2 drops all TCP to the mail server except port 25. So replies to connections *it* opens (e.g. relaying mail to other SMTP servers) are blocked. This assumes the mail server also has a per-host allow rule further down, which the ACL implies ("one rule for every internal IP address") but doesn't show.

## General
- The answers were written short and in plain language on purpose. If the course expects the paper to be cited, add references like "(Mugala, p. 8)" where an answer comes from it: Q8–Q10, Q13–Q15, Q20, Q22, Q23 (proxy), Q25 and Q27.
- Fill in the names before submitting.
