from pathlib import Path

from netscope.analyzer import analyze_packets
from netscope.parser import parse_pcap

ROOT = Path(__file__).resolve().parents[1]


def test_demo_triggers_expected_detection_families() -> None:
    packets = parse_pcap((ROOT / "data" / "demo-traffic.pcap").read_bytes())
    result = analyze_packets(packets, "demo.pcap")
    rule_ids = {alert["rule_id"] for alert in result["alerts"]}

    assert result["meta"]["packets"] == 94
    assert result["meta"]["flows"] > 10
    assert {
        "NS-PORT-SCAN",
        "NS-SYN-BURST",
        "NS-DNS-ENTROPY",
        "NS-PERIODIC-BEACON",
        "NS-LARGE-TRANSFER",
        "NS-ICMP-SWEEP",
        "NS-ARP-CONFLICT",
    }.issubset(rule_ids)


def test_flow_direction_counts_sum_to_packet_count() -> None:
    packets = parse_pcap((ROOT / "data" / "demo-traffic.pcap").read_bytes())
    result = analyze_packets(packets)
    for flow in result["flows"]:
        assert flow["forward_packets"] + flow["reverse_packets"] == flow["packets"]
        assert flow["bytes"] > 0
        assert flow["duration_seconds"] >= 0


def test_analysis_is_json_serializable() -> None:
    import json

    packets = parse_pcap((ROOT / "data" / "demo-traffic.pcap").read_bytes())
    result = analyze_packets(packets)
    encoded = json.dumps(result)
    assert '"alerts"' in encoded
    assert '"flows"' in encoded
