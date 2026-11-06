from pathlib import Path

import pytest

from netscope.parser import PcapParseError, parse_pcap

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "demo-traffic.pcap"


def test_parses_bundled_capture_and_protocols() -> None:
    packets = parse_pcap(SAMPLE.read_bytes())
    assert len(packets) == 94
    protocols = {packet.transport for packet in packets}
    assert {"TCP", "UDP", "ICMP", "ARP"}.issubset(protocols)
    assert any(packet.dns_query and packet.dns_query.endswith(".example") for packet in packets)
    assert any(packet.arp_sender_ip == "10.0.0.1" for packet in packets)


def test_rejects_unknown_magic() -> None:
    with pytest.raises(PcapParseError, match="Unrecognised capture format"):
        parse_pcap(b"not-a-pcap" + b"\x00" * 50)


def test_rejects_truncated_record() -> None:
    data = SAMPLE.read_bytes()[:35]
    with pytest.raises(PcapParseError):
        parse_pcap(data)


def test_enforces_packet_limit() -> None:
    with pytest.raises(PcapParseError, match="analysis limit"):
        parse_pcap(SAMPLE.read_bytes(), max_packets=10)
