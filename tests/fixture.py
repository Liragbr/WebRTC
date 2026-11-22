"""Deterministic Ethernet/IPv4/UDP capture. All addresses are laboratory examples."""

import struct
import sys
from ipaddress import ip_address
from pathlib import Path

LOCAL = "192.0.2.10"
EXPECTED = "198.51.100.7"
OTHER = "203.0.113.9"
# Fixed wire vectors, independent from the application decoder.
DIRECT = bytes.fromhex("0101000c2112a442000102030405060708090a0b 0020000800012c84ea12d54b")
VPN = bytes.fromhex("0101000c2112a442000102030405060708090a0c 0020000800012c84e721c045")


def frame(payload, destination=LOCAL):
    udp = struct.pack("!HHHH", 3478, 50000, len(payload) + 8, 0) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(udp) + 20,
        1,
        0,
        64,
        17,
        0,
        ip_address("192.0.2.1").packed,
        ip_address(destination).packed,
    )
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    header = header[:10] + struct.pack("!H", total ^ 65535) + header[12:]
    return bytes.fromhex("0200000000010200000000020800") + header + udp


def write(path):
    packets = [
        frame(VPN),
        frame(DIRECT),
        frame(DIRECT, "192.0.2.99"),
        frame(DIRECT[:-1]),
        frame(b"unrelated udp"),
    ]
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for offset, packet in enumerate(packets):
            output.write(struct.pack("<IIII", 1700000000 + offset, 0, len(packet), len(packet)))
            output.write(packet)


if __name__ == "__main__":
    write(Path(sys.argv[1]))
