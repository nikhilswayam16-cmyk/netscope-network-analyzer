#!/usr/bin/env python3
"""Generate a deterministic, synthetic PCAP used by NetScope's demo mode."""
from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def ethernet(payload: bytes, ethertype: int = 0x0800, src_mac: str = "02:00:00:00:00:01", dst_mac: str = "02:00:00:00:00:02") -> bytes:
    return mac(dst_mac) + mac(src_mac) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, protocol: int, payload: bytes, identification: int = 1) -> bytes:
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, identification & 0xFFFF, 0x4000, 64, protocol, 0, ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    csum = checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def tcp(src: str, dst: str, sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 1, ack: int = 0) -> bytes:
    offset_reserved = 5 << 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, offset_reserved, flags, 64240, 0, 0)
    pseudo = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return header + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!BBH", 0, 17, length)
    csum = checksum(pseudo + header + payload)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


def dns_query(name: str, ident: int) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def arp(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + mac(sender_mac) + ipaddress.IPv4Address(sender_ip).packed
        + mac(target_mac) + ipaddress.IPv4Address(target_ip).packed
    )


def build_capture() -> bytes:
    packets: list[tuple[float, bytes]] = []
    base = 1_735_000_000.0
    client_mac = "02:10:00:00:00:20"
    server_mac = "02:10:00:00:00:10"
    internet_mac = "02:10:00:00:00:fe"

    def add(ts: float, frame: bytes) -> None:
        packets.append((base + ts, frame))

    # Ordinary background traffic: DNS, HTTPS and HTTP.
    add(0.1, ethernet(ipv4("10.0.0.20", "8.8.8.8", 17, udp("10.0.0.20", "8.8.8.8", 53000, 53, dns_query("example.com", 1))), src_mac=client_mac, dst_mac=internet_mac))
    add(0.2, ethernet(ipv4("8.8.8.8", "10.0.0.20", 17, udp("8.8.8.8", "10.0.0.20", 53, 53000, struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0))), src_mac=internet_mac, dst_mac=client_mac))
    add(0.4, ethernet(ipv4("10.0.0.20", "93.184.216.34", 6, tcp("10.0.0.20", "93.184.216.34", 51515, 443, 0x02)), src_mac=client_mac, dst_mac=internet_mac))
    add(0.5, ethernet(ipv4("93.184.216.34", "10.0.0.20", 6, tcp("93.184.216.34", "10.0.0.20", 443, 51515, 0x12, seq=10, ack=2)), src_mac=internet_mac, dst_mac=client_mac))
    add(0.6, ethernet(ipv4("10.0.0.20", "93.184.216.34", 6, tcp("10.0.0.20", "93.184.216.34", 51515, 443, 0x10, seq=2, ack=11)), src_mac=client_mac, dst_mac=internet_mac))
    add(0.8, ethernet(ipv4("10.0.0.21", "10.0.0.5", 6, tcp("10.0.0.21", "10.0.0.5", 52001, 80, 0x02)), src_mac="02:10:00:00:00:21", dst_mac=server_mac))

    # Vertical port scan: many destination ports on a single target.
    scan_source, scan_target = "10.0.0.50", "10.0.0.10"
    for index, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]):
        segment = tcp(scan_source, scan_target, 41000 + index, port, 0x02, seq=100 + index)
        add(2 + index * 0.08, ethernet(ipv4(scan_source, scan_target, 6, segment, identification=100 + index), src_mac="02:10:00:00:00:50", dst_mac=server_mac))

    # SYN burst concentrated on a single service.
    for index in range(26):
        src, dst = "10.0.0.60", "10.0.0.10"
        segment = tcp(src, dst, 42000 + index, 443, 0x02, seq=300 + index)
        add(4 + index * 0.03, ethernet(ipv4(src, dst, 6, segment, identification=300 + index), src_mac="02:10:00:00:00:60", dst_mac=server_mac))

    # Long / high-entropy DNS labels (heuristic example, not proof of tunnelling).
    for index, label in enumerate([
        "mfrggzdfmztwq2lkobwgk4tfon2g64tmmq2dkzjsgm2gkzls",
        "jbswy3dpehpk3pxp7v6e2m4q9w3k8r5n1c6x0z7a2b4d9f",
        "q7m2v9x4k8p3n6w1c5z0r2t7b4d8f9h3j6l1s5u0a2e7g4",
    ]):
        src, dst = "10.0.0.70", "8.8.8.8"
        qname = f"{label}.telemetry.example"
        segment = udp(src, dst, 53070, 53, dns_query(qname, 50 + index))
        add(6 + index * 0.7, ethernet(ipv4(src, dst, 17, segment, identification=500 + index), src_mac="02:10:00:00:00:70", dst_mac=internet_mac))

    # Periodic connection pattern: six SYN attempts at stable 30-second intervals.
    for index in range(6):
        src, dst = "10.0.0.80", "93.184.216.34"
        segment = tcp(src, dst, 43111, 8443, 0x02, seq=600 + index)
        add(10 + index * 30, ethernet(ipv4(src, dst, 6, segment, identification=600 + index), src_mac="02:10:00:00:00:80", dst_mac=internet_mac))

    # Large outbound data stream: 24 payload-bearing frames, >1 MiB total.
    for index in range(24):
        src, dst = "10.0.0.90", "93.184.216.34"
        payload = (b"NETSCOPE-SYNTHETIC-PAYLOAD-" + bytes([65 + (index % 26)])) * 1900
        segment = tcp(src, dst, 44000, 9000, 0x18, payload=payload, seq=1000 + index * len(payload), ack=1)
        add(190 + index * 0.15, ethernet(ipv4(src, dst, 6, segment, identification=800 + index), src_mac="02:10:00:00:00:90", dst_mac=internet_mac))

    # ARP ownership conflict: two MAC addresses claim the same gateway IP.
    add(195, ethernet(arp("02:10:00:00:00:01", "10.0.0.1", "00:00:00:00:00:00", "10.0.0.254"), 0x0806, "02:10:00:00:00:01", "ff:ff:ff:ff:ff:ff"))
    add(196, ethernet(arp("02:10:00:00:00:99", "10.0.0.1", "00:00:00:00:00:00", "10.0.0.254"), 0x0806, "02:10:00:00:00:99", "ff:ff:ff:ff:ff:ff"))

    # ICMP host sweep across an isolated documentation subnet.
    for index in range(12):
        src, dst = "10.0.0.110", f"198.51.100.{10 + index}"
        icmp = struct.pack("!BBHHH", 8, 0, 0, 900 + index, 1)
        add(197 + index * 0.02, ethernet(ipv4(src, dst, 1, icmp, identification=1000 + index), src_mac="02:10:00:00:00:aa", dst_mac=internet_mac))

    packets.sort(key=lambda item: item[0])
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    output = bytearray(global_header)
    for timestamp, frame in packets:
        seconds = int(timestamp)
        micros = int(round((timestamp - seconds) * 1_000_000))
        if micros >= 1_000_000:
            seconds += 1
            micros -= 1_000_000
        output.extend(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/demo-traffic.pcap")
    args = parser.parse_args()
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = build_capture()
    destination.write_bytes(data)
    print(f"Wrote {destination} · {len(data):,} bytes")


if __name__ == "__main__":
    main()
