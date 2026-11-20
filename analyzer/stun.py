"""Decode one complete RFC 8489 UDP Binding success response."""

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

COOKIE = bytes.fromhex("2112a442")


@dataclass(frozen=True)
class Mapping:
    address: IPv4Address | IPv6Address
    port: int
    transaction: str


def parse(data: bytes) -> Mapping | None:
    if len(data) < 20 or data[:2] != b"\x01\x01" or data[4:8] != COOKIE:
        return None
    length = int.from_bytes(data[2:4], "big")
    if length % 4 or length != len(data) - 20:
        return None
    start = 20
    result = None
    while start < len(data):
        kind, size = struct.unpack_from("!HH", data, start)
        start += 4
        end = start + size
        if end > len(data):
            return None
        if kind == 0x0020 and result is None:
            value = data[start:end]
            if len(value) < 4 or {1: 8, 2: 20}.get(value[1]) != size:
                return None
            port = int.from_bytes(value[2:4], "big") ^ 0x2112
            raw = bytes(a ^ b for a, b in zip(value[4:], data[4:20]))
            result = Mapping(ip_address(raw), port, data[8:20].hex())
        start += (size + 3) & ~3
    return result
