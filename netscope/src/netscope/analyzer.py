"""Flow aggregation and explainable network anomaly rules."""

from __future__ import annotations

import hashlib
import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from statistics import mean, pstdev
from typing import Any, Iterable

from .parser import PacketRecord


@dataclass(slots=True)
class Flow:
    flow_id: str
    src: str
    dst: str
    src_port: int | None
    dst_port: int | None
    transport: str
    app_protocol: str
    packets: int = 0
    bytes: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    syn: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    duration_seconds: float = 0.0

    def add(self, packet: PacketRecord, forward: bool) -> None:
        if self.packets == 0:
            self.first_seen = packet.timestamp
            self.last_seen = packet.timestamp
        self.packets += 1
        self.bytes += packet.length
        self.forward_packets += int(forward)
        self.reverse_packets += int(not forward)
        self.last_seen = max(self.last_seen, packet.timestamp)
        self.first_seen = min(self.first_seen, packet.timestamp)
        self.duration_seconds = max(0.0, self.last_seen - self.first_seen)
        self.syn += int("S" in packet.tcp_flags)
        self.ack += int("A" in packet.tcp_flags)
        self.fin += int("F" in packet.tcp_flags)
        self.rst += int("R" in packet.tcp_flags)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _endpoint(ip: str | None, port: int | None) -> tuple[str, int]:
    return (ip or "unknown", -1 if port is None else port)


def _stable_flow_id(key: tuple[Any, ...]) -> str:
    digest = hashlib.sha1(repr(key).encode("utf-8")).hexdigest()[:10]
    return f"flow-{digest}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value.lower())
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified)
    except ValueError:
        return False


def _alert(
    rule_id: str,
    title: str,
    severity: str,
    src: str,
    dst: str,
    summary: str,
    evidence: list[str],
    mitre: str,
    confidence: int,
    first_seen: float | None = None,
) -> dict[str, Any]:
    raw = f"{rule_id}|{src}|{dst}|{title}"
    return {
        "id": "NS-" + hashlib.sha1(raw.encode()).hexdigest()[:8].upper(),
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "source": src,
        "destination": dst,
        "summary": summary,
        "evidence": evidence,
        "mitre": mitre,
        "confidence": confidence,
        "first_seen": first_seen,
    }


def _build_flows(packets: list[PacketRecord]) -> list[Flow]:
    flow_map: dict[tuple[Any, ...], Flow] = {}
    original_direction: dict[tuple[Any, ...], tuple[tuple[str, int], tuple[str, int]]] = {}
    for packet in packets:
        if not packet.src or not packet.dst:
            continue
        src_ep = _endpoint(packet.src, packet.src_port)
        dst_ep = _endpoint(packet.dst, packet.dst_port)
        ordered = tuple(sorted((src_ep, dst_ep)))
        key = (packet.transport, ordered[0], ordered[1])
        if key not in flow_map:
            flow_map[key] = Flow(
                flow_id=_stable_flow_id(key),
                src=packet.src,
                dst=packet.dst,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                transport=packet.transport,
                app_protocol=packet.app_protocol,
            )
            original_direction[key] = (src_ep, dst_ep)
        forward = src_ep == original_direction[key][0]
        flow_map[key].add(packet, forward)
    return sorted(flow_map.values(), key=lambda item: item.bytes, reverse=True)


def analyze_packets(packets: list[PacketRecord], filename: str = "capture.pcap") -> dict[str, Any]:
    """Build overview, bidirectional flows, talkers, protocol stats and alerts."""
    if not packets:
        raise ValueError("No packets to analyze.")

    flows = _build_flows(packets)
    total_bytes = sum(packet.length for packet in packets)
    start = min(packet.timestamp for packet in packets)
    end = max(packet.timestamp for packet in packets)
    protocol_counts = Counter(packet.app_protocol for packet in packets)
    protocol_bytes: Counter[str] = Counter()
    source_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "destinations": 0})
    source_destinations: dict[str, set[str]] = defaultdict(set)
    directed_bytes: Counter[tuple[str, str]] = Counter()
    directed_packets: dict[tuple[str, str], list[PacketRecord]] = defaultdict(list)
    scan_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    syn_bursts: Counter[tuple[str, str, int | None]] = Counter()
    dns_by_source: dict[str, list[tuple[str, float]]] = defaultdict(list)
    arp_claims: dict[str, set[str]] = defaultdict(set)
    icmp_hosts: dict[str, set[str]] = defaultdict(set)

    for packet in packets:
        protocol_bytes[packet.app_protocol] += packet.length
        if packet.src:
            source_stats[packet.src]["packets"] += 1
            source_stats[packet.src]["bytes"] += packet.length
            if packet.dst:
                source_destinations[packet.src].add(packet.dst)
                directed_bytes[(packet.src, packet.dst)] += packet.length
                directed_packets[(packet.src, packet.dst)].append(packet)
        if packet.transport == "TCP" and packet.src and packet.dst:
            if packet.dst_port is not None:
                if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
                    scan_ports[(packet.src, packet.dst)].add(packet.dst_port)
                    syn_bursts[(packet.src, packet.dst, packet.dst_port)] += 1
        if packet.dns_query and packet.src:
            dns_by_source[packet.src].append((packet.dns_query, packet.timestamp))
        if packet.arp_sender_ip and packet.arp_sender_mac:
            arp_claims[packet.arp_sender_ip].add(packet.arp_sender_mac)
        if packet.transport in ("ICMP", "ICMPv6") and packet.src and packet.dst:
            icmp_hosts[packet.src].add(packet.dst)

    # Port scan: many distinct destination ports from one source to one target.
    alerts: list[dict[str, Any]] = []
    for (src, dst), ports in scan_ports.items():
        if len(ports) >= 10:
            sample_ports = sorted(ports)[:12]
            alerts.append(_alert(
                "NS-PORT-SCAN", "Vertical port scan", "high", src, dst,
                f"One source sent TCP SYN probes to {len(ports)} distinct destination ports on a single host.",
                [f"Unique destination ports: {len(ports)}", f"Observed ports: {', '.join(map(str, sample_ports))}", "Packets were SYN-only (no ACK) in the captured sample."],
                "T1595.001 · Active Scanning: Scanning IP Blocks", 96,
            ))

    # SYN burst: concentrated SYN-only attempts against a small number of services.
    for (src, dst, port), count in syn_bursts.items():
        if count >= 20 and len(scan_ports.get((src, dst), set())) < 10:
            alerts.append(_alert(
                "NS-SYN-BURST", "High-volume SYN burst", "high", src, dst,
                f"{count} TCP SYN packets targeted service port {port} without a corresponding ACK in this capture.",
                [f"SYN-only packets: {count}", f"Destination service port: {port}", "A packet capture alone cannot prove service impact or successful connection state."],
                "T1498.001 · Network Denial of Service: Direct Network Flood", 91,
            ))

    # DNS label heuristic. This flags suspiciously long / high-entropy names, not proof of tunnelling.
    dns_suspicious: dict[str, list[str]] = defaultdict(list)
    for src, queries in dns_by_source.items():
        for qname, _timestamp in queries:
            labels = qname.split(".")
            longest = max((len(label) for label in labels), default=0)
            left_entropy = _entropy(labels[0]) if labels else 0.0
            if len(qname) >= 55 or (longest >= 32 and left_entropy >= 3.4):
                dns_suspicious[src].append(qname)
    for src, names in dns_suspicious.items():
        unique_names = list(dict.fromkeys(names))
        alerts.append(_alert(
            "NS-DNS-ENTROPY", "Unusually long / high-entropy DNS names", "medium", src, "DNS resolvers",
            f"Observed {len(names)} DNS question(s) with long or high-entropy labels; this can be consistent with tunnelling or encoded identifiers.",
            [f"Distinct suspicious names: {len(unique_names)}", f"Example query: {unique_names[0][:100]}", "Heuristic only: CDNs, tracking systems and legitimate software can also produce long labels."],
            "T1071.004 · Application Layer Protocol: DNS", 78,
        ))

    # Beaconing: repeated TCP SYN or UDP events with low interval variance.
    event_groups: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    for packet in packets:
        if not packet.src or not packet.dst or packet.dst_port is None:
            continue
        is_connection_event = packet.transport == "UDP" or (packet.transport == "TCP" and "S" in packet.tcp_flags and "A" not in packet.tcp_flags)
        if is_connection_event:
            event_groups[(packet.src, packet.dst, packet.dst_port, packet.transport)].append(packet.timestamp)
    for (src, dst, port, transport), times in event_groups.items():
        ordered_times = sorted(set(times))
        intervals = [b - a for a, b in zip(ordered_times, ordered_times[1:]) if b > a]
        if len(intervals) >= 4:
            avg = mean(intervals)
            cv = (pstdev(intervals) / avg) if avg else 1.0
            if 5 <= avg <= 900 and cv <= 0.15:
                alerts.append(_alert(
                    "NS-PERIODIC-BEACON", "Regular periodic connection pattern", "medium", src, dst,
                    f"{len(ordered_times)} connection events repeated about every {avg:.1f} seconds (interval CV {cv:.2f}).",
                    [f"Mean interval: {avg:.1f}s", f"Interval coefficient of variation: {cv:.2f}", f"Destination port: {port}/{transport}"],
                    "T1071 · Application Layer Protocol", 73, min(ordered_times),
                ))

    # Large outbound transfer from private/internal source to public destination.
    for (src, dst), byte_count in directed_bytes.items():
        try:
            is_internal = ipaddress.ip_address(src).is_private
        except ValueError:
            is_internal = False
        if is_internal and _is_public_ip(dst) and byte_count >= 1_000_000:
            alerts.append(_alert(
                "NS-LARGE-TRANSFER", "Large outbound data transfer", "high", src, dst,
                f"The source sent {byte_count / (1024 * 1024):.2f} MiB to a public destination within this capture.",
                [f"Observed bytes: {byte_count:,}", "Threshold: 1,000,000 bytes per source/destination pair", "Encrypted payload contents are not inspected; byte volume alone does not establish exfiltration."],
                "T1041 · Exfiltration Over C2 Channel", 82,
            ))

    # ICMP sweep: one source probes many unique destination hosts.
    for src, destinations in icmp_hosts.items():
        if len(destinations) >= 10:
            alerts.append(_alert(
                "NS-ICMP-SWEEP", "ICMP host sweep", "medium", src, "Multiple hosts",
                f"ICMP traffic from this source touched {len(destinations)} distinct destination addresses.",
                [f"Distinct destinations: {len(destinations)}", f"Examples: {', '.join(sorted(destinations)[:8])}"],
                "T1046 · Network Service Discovery", 80,
            ))

    # ARP conflict: different MAC addresses claim one IPv4 sender address.
    for claimed_ip, macs in arp_claims.items():
        if len(macs) > 1:
            alerts.append(_alert(
                "NS-ARP-CONFLICT", "Conflicting ARP address ownership", "high", "Layer 2 segment", claimed_ip,
                f"Multiple MAC addresses claimed sender IP {claimed_ip} in the capture.",
                [f"Claiming MAC addresses: {', '.join(sorted(macs))}", "This may indicate ARP spoofing, proxy ARP, failover or a capture artefact; verify against network inventory."],
                "T1557.002 · Adversary-in-the-Middle: ARP Cache Poisoning", 85,
            ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda item: (severity_order.get(item["severity"], 9), item["title"]))

    for src, values in source_stats.items():
        values["destinations"] = len(source_destinations[src])
    top_talkers = [
        {"ip": ip, **values}
        for ip, values in sorted(source_stats.items(), key=lambda pair: pair[1]["bytes"], reverse=True)[:10]
    ]
    protocol_stats = [
        {"protocol": protocol, "packets": count, "bytes": protocol_bytes[protocol]}
        for protocol, count in protocol_counts.most_common()
    ]

    return {
        "meta": {
            "filename": filename,
            "packets": len(packets),
            "bytes": total_bytes,
            "duration_seconds": round(max(0.0, end - start), 3),
            "start_time": start,
            "end_time": end,
            "flows": len(flows),
            "sources": len(source_stats),
            "destinations": len({p.dst for p in packets if p.dst}),
        },
        "protocols": protocol_stats,
        "top_talkers": top_talkers,
        "flows": [flow.to_dict() for flow in flows[:500]],
        "alerts": alerts,
        "packet_preview": [packet.to_dict() for packet in packets[:100]],
        "rules": [
            {"id": "NS-PORT-SCAN", "name": "Vertical port scan", "threshold": "10+ unique TCP destination ports", "confidence": "High"},
            {"id": "NS-SYN-BURST", "name": "High-volume SYN burst", "threshold": "20+ SYN-only packets to one service", "confidence": "High"},
            {"id": "NS-DNS-ENTROPY", "name": "Long / high-entropy DNS", "threshold": "55+ chars or long high-entropy label", "confidence": "Medium"},
            {"id": "NS-PERIODIC-BEACON", "name": "Periodic connection pattern", "threshold": "5+ events, 5–900s interval, CV ≤ 0.15", "confidence": "Medium"},
            {"id": "NS-LARGE-TRANSFER", "name": "Large outbound transfer", "threshold": "1,000,000+ bytes to public IP", "confidence": "Medium"},
            {"id": "NS-ICMP-SWEEP", "name": "ICMP host sweep", "threshold": "10+ unique destinations", "confidence": "Medium"},
            {"id": "NS-ARP-CONFLICT", "name": "Conflicting ARP ownership", "threshold": "2+ MACs claiming same IPv4", "confidence": "Medium"},
        ],
    }
