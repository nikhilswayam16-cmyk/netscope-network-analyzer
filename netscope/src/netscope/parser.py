"""A bounded, dependency-light classic PCAP parser.

Supports classic PCAP (microsecond and nanosecond timestamps) with Ethernet,
raw IP, and Linux cooked v1 link layers. It decodes IPv4/IPv6, TCP, UDP, ICMP,
ARP, and uncompressed DNS question names. It never executes packet payloads.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import asdict, dataclass
from typing import Any


class PcapParseError(ValueError):
    """Raised when a capture is malformed, unsupported, or exceeds a bound."""


@dataclass(slots=True)
class PacketRecord:
    timestamp: float
    src: str | None
    dst: str | None
    src_port: int | None
    dst_port: int | None
    transport: str
    app_protocol: str
    length: int
    tcp_flags: str = ""
    dns_query: str | None = None
    ttl: int | None = None
    ip_version: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_ip: str | None = None
    arp_sender_mac: str | None = None
    icmp_type: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Classic PCAP magic byte sequences.
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = 101
_LINKTYPE_LINUX_SLL = 113

_PORT_NAMES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS/TLS",
    445: "SMB", 465: "SMTPS", 514: "SYSLOG", 587: "SMTP-SUBMISSION",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL", 6379: "REDIS",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB",
}


def _mac(raw: bytes) -> str:
    return ":".join(f"{part:02x}" for part in raw)


def _app_protocol(transport: str, src_port: int | None, dst_port: int | None) -> str:
    ports = {p for p in (src_port, dst_port) if p is not None}
    for port in sorted(ports):
        if port in _PORT_NAMES:
            name = _PORT_NAMES[port]
            if name == "DNS" and transport != "UDP":
                continue
            return name
    return transport


def _dns_question(payload: bytes) -> str | None:
    """Extract a first DNS question name; compression pointers are rejected safely."""
    if len(payload) < 17:
        return None
    qdcount = struct.unpack_from("!H", payload, 4)[0]
    if qdcount < 1:
        return None
    labels: list[str] = []
    offset = 12
    consumed = 0
    try:
        while offset < len(payload):
            size = payload[offset]
            offset += 1
            consumed += 1
            if size == 0:
                break
            # A pointer or an invalid label is not needed for a query name.
            if size & 0xC0 or size > 63 or offset + size > len(payload):
                return None
            label = payload[offset:offset + size].decode("ascii", errors="replace")
            labels.append(label)
            offset += size
            consumed += size
            if consumed > 255:
                return None
        if not labels:
            return None
        return ".".join(labels)[:253]
    except (IndexError, struct.error):
        return None


def _parse_transport(
    packet: bytes,
    offset: int,
    protocol_number: int,
    timestamp: float,
    src: str,
    dst: str,
    frame_len: int,
    ttl: int | None,
    ip_version: int,
    src_mac: str | None,
    dst_mac: str | None,
) -> PacketRecord | None:
    src_port: int | None = None
    dst_port: int | None = None
    flags = ""
    dns_query = None
    icmp_type = None
    transport = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(protocol_number)
    if transport == "TCP":
        if len(packet) < offset + 20:
            return None
        src_port, dst_port = struct.unpack_from("!HH", packet, offset)
        data_offset = (packet[offset + 12] >> 4) * 4
        if data_offset < 20 or len(packet) < offset + data_offset:
            return None
        flag_bits = packet[offset + 13]
        flags = "".join(letter for bit, letter in ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U")) if flag_bits & bit)
    elif transport == "UDP":
        if len(packet) < offset + 8:
            return None
        src_port, dst_port = struct.unpack_from("!HH", packet, offset)
        udp_payload = packet[offset + 8:]
        if 53 in (src_port, dst_port):
            dns_query = _dns_question(udp_payload)
    elif transport in ("ICMP", "ICMPv6"):
        if len(packet) < offset + 2:
            return None
        icmp_type = packet[offset]
    else:
        return None

    return PacketRecord(
        timestamp=timestamp,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        app_protocol=_app_protocol(transport, src_port, dst_port),
        length=frame_len,
        tcp_flags=flags,
        dns_query=dns_query,
        ttl=ttl,
        ip_version=ip_version,
        src_mac=src_mac,
        dst_mac=dst_mac,
        icmp_type=icmp_type,
    )


def _decode_frame(frame: bytes, timestamp: float, linktype: int) -> PacketRecord | None:
    offset = 0
    src_mac = dst_mac = None
    ether_type: int | None = None

    if linktype == _LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        dst_mac, src_mac = _mac(frame[0:6]), _mac(frame[6:12])
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        vlan_depth = 0
        while ether_type in (0x8100, 0x88A8, 0x9100) and vlan_depth < 2:
            if len(frame) < offset + 4:
                return None
            ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
            vlan_depth += 1
    elif linktype == _LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        ether_type = struct.unpack_from("!H", frame, 14)[0]
        offset = 16
    elif linktype == _LINKTYPE_RAW:
        if not frame:
            return None
        version = frame[0] >> 4
        ether_type = 0x0800 if version == 4 else 0x86DD if version == 6 else None
    else:
        raise PcapParseError(f"Unsupported PCAP link type {linktype}. Supported: Ethernet (1), RAW IP (101), Linux SLL (113).")

    if ether_type == 0x0806:  # ARP
        if len(frame) < offset + 28:
            return None
        htype, ptype, hlen, plen, _opcode = struct.unpack_from("!HHBBH", frame, offset)
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
            return None
        cursor = offset + 8
        sender_mac = _mac(frame[cursor:cursor + 6])
        sender_ip = str(ipaddress.IPv4Address(frame[cursor + 6:cursor + 10]))
        target_mac = _mac(frame[cursor + 10:cursor + 16])
        target_ip = str(ipaddress.IPv4Address(frame[cursor + 16:cursor + 20]))
        return PacketRecord(
            timestamp, sender_ip, target_ip, None, None, "ARP", "ARP", len(frame),
            src_mac=src_mac or sender_mac, dst_mac=dst_mac or target_mac,
            arp_sender_ip=sender_ip, arp_target_ip=target_ip, arp_sender_mac=sender_mac,
        )

    if ether_type == 0x0800:  # IPv4
        if len(frame) < offset + 20:
            return None
        first = frame[offset]
        if first >> 4 != 4:
            return None
        ihl = (first & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return None
        total_len = struct.unpack_from("!H", frame, offset + 2)[0]
        if total_len < ihl:
            return None
        fragment = struct.unpack_from("!H", frame, offset + 6)[0]
        if fragment & 0x1FFF:  # Non-first fragments do not begin with a transport header.
            return None
        ttl = frame[offset + 8]
        proto = frame[offset + 9]
        src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
        dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
        end = min(len(frame), offset + total_len)
        return _parse_transport(frame[:end], offset + ihl, proto, timestamp, src, dst, len(frame), ttl, 4, src_mac, dst_mac)

    if ether_type == 0x86DD:  # IPv6
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            return None
        payload_len = struct.unpack_from("!H", frame, offset + 4)[0]
        next_header = frame[offset + 6]
        ttl = frame[offset + 7]
        src = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
        dst = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
        cursor = offset + 40
        end = min(len(frame), cursor + payload_len)
        # Skip common IPv6 extension headers with bounded traversal.
        for _ in range(8):
            if next_header in (0, 43, 60):  # Hop-by-hop, routing, destination options
                if cursor + 2 > end:
                    return None
                length = (frame[cursor + 1] + 1) * 8
                next_header, cursor = frame[cursor], cursor + length
            elif next_header == 44:  # Fragment
                if cursor + 8 > end:
                    return None
                fragment_field = struct.unpack_from("!H", frame, cursor + 2)[0]
                if fragment_field & 0xFFF8:
                    return None
                next_header, cursor = frame[cursor], cursor + 8
            elif next_header == 51:  # Authentication header
                if cursor + 2 > end:
                    return None
                length = (frame[cursor + 1] + 2) * 4
                next_header, cursor = frame[cursor], cursor + length
            else:
                break
        return _parse_transport(frame[:end], cursor, next_header, timestamp, src, dst, len(frame), ttl, 6, src_mac, dst_mac)

    return None


def parse_pcap(data: bytes, *, max_packets: int = 50_000, max_frame_bytes: int = 1_048_576) -> list[PacketRecord]:
    """Parse a classic PCAP byte string into packet records under strict bounds."""
    if len(data) < 24:
        raise PcapParseError("File is too small to be a classic PCAP capture.")
    magic = data[:4]
    if magic not in _MAGIC:
        raise PcapParseError("Unrecognised capture format. Upload a classic .pcap file (pcapng is not supported yet).")
    endian, ticks_per_second = _MAGIC[magic]
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
    if major != 2 or minor not in (2, 3, 4):
        raise PcapParseError(f"Unsupported PCAP version {major}.{minor}; expected 2.2–2.4.")
    if snaplen == 0 or snaplen > max_frame_bytes:
        raise PcapParseError(f"Capture snap length {snaplen} is outside the allowed range (1–{max_frame_bytes}).")
    if linktype not in (_LINKTYPE_ETHERNET, _LINKTYPE_RAW, _LINKTYPE_LINUX_SLL):
        raise PcapParseError(f"Unsupported PCAP link type {linktype}. Supported: Ethernet, RAW IP, Linux SLL.")

    records: list[PacketRecord] = []
    cursor = 24
    while cursor < len(data):
        if len(records) >= max_packets:
            raise PcapParseError(f"Capture exceeds the {max_packets:,}-packet analysis limit.")
        if cursor + 16 > len(data):
            raise PcapParseError("Capture ends in the middle of a packet record header.")
        seconds, fraction, captured_len, original_len = struct.unpack_from(endian + "IIII", data, cursor)
        cursor += 16
        if fraction >= ticks_per_second:
            raise PcapParseError("Packet timestamp fraction is outside the capture's timestamp resolution.")
        if captured_len > snaplen:
            raise PcapParseError("Captured packet length exceeds the capture's declared snap length.")
        if original_len < captured_len:
            raise PcapParseError("Original packet length is smaller than the captured packet length.")
        if captured_len > max_frame_bytes:
            raise PcapParseError(f"Packet size {captured_len} exceeds the {max_frame_bytes:,}-byte frame limit.")
        if captured_len > len(data) - cursor:
            raise PcapParseError("Capture ends before the complete packet data is available.")
        frame = data[cursor:cursor + captured_len]
        cursor += captured_len
        timestamp = seconds + fraction / ticks_per_second
        record = _decode_frame(frame, timestamp, linktype)
        if record is not None:
            records.append(record)
    if not records:
        raise PcapParseError("No supported Ethernet/IP/ARP packets were found in this capture.")
    return records
