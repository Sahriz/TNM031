"""The command-line runner must still print and save the detector's findings."""

import json
import sys

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

import run


def test_runner_reports_each_new_alert_once(tmp_path, monkeypatch, capsys):
    # End-to-end check of PCAP -> runner -> detector -> JSON.
    # Three probes trigger once, then refresh; stdout should print one finding while
    # the saved record contains the final count and evidence. This also checks that
    # command-line configuration and the optional host-status output are connected.
    packets = []
    for index, port in enumerate((80, 81, 82)):
        packet = Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(
            sport=40000 + index, dport=port, flags="S")
        packet.time = 100 + index
        packets.append(packet)
    capture_path = tmp_path / "scan.pcap"
    wrpcap(str(capture_path), packets)

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"port_scan": {"threshold": 2}}))
    alerts_path = tmp_path / "alerts.jsonl"
    status_path = tmp_path / "status.json"
    monkeypatch.setattr(sys, "argv", ["run.py", str(capture_path), "--config", str(config_path),
                                      "--out", str(alerts_path), "--status", str(status_path)])
    run.main()

    output = capsys.readouterr().out
    assert output.count("port_scan/portscan") == 1
    assert "[    1.00s]" in output
    assert "3 packets, 1 alerts written" in output
    [alert] = [json.loads(line) for line in alerts_path.read_text().splitlines()]
    assert alert["ts"] == 101
    assert alert["count"] == 2  # The third SYN refreshes the existing alert.
    assert alert["evidence"]["distinct_targets"] == 3
    status = json.loads(status_path.read_text())
    assert status["10.0.0.2"]["status"] == "medium"
