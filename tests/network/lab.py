"""In isolated Linux namespaces, compare TShark's result to the server's UDP peer."""

import socket
import struct
import sys
import threading
from ipaddress import ip_address

from analyzer.capture import command, run
from analyzer.enrichment import assess, baseline

CLIENT = "192.0.2.10"
SERVER = "198.51.100.2"
COOKIE = bytes.fromhex("2112a442")
TRANSACTION = bytes.fromhex("000102030405060708090a0b")


def serve():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((SERVER, 3478))
        while True:
            request, peer = udp.recvfrom(512)
            if request != b"\x00\x01\x00\x00" + COOKIE + TRANSACTION:
                continue
            address = int(ip_address(peer[0])) ^ int.from_bytes(COOKIE, "big")
            attr = struct.pack("!HHBBHI", 32, 8, 0, 1, peer[1] ^ 0x2112, address)
            udp.sendto(b"\x01\x01\x00\x0c" + request[4:] + attr, peer)


def check(observed, allowed):
    cancel = threading.Event()
    records = []

    def send_requests():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind((CLIENT, 0))
            while not cancel.wait(0.15):
                udp.sendto(b"\x00\x01\x00\x00" + COOKIE + TRANSACTION, (SERVER, 3478))

    def collect(mapping):
        records.append(mapping)
        cancel.set()

    sender = threading.Thread(target=send_requests)
    sender.start()
    try:
        run(command(CLIENT, interface="lab0", duration=10), cancel, collect, timeout=15)
    finally:
        cancel.set()
        sender.join()
    if not records or str(records[0].address) != observed:
        raise RuntimeError(f"Expected {observed}, received {records}")
    verdict = assess(records[0].address, baseline(allowed))
    if (verdict == "saída prevista") != (observed == allowed):
        raise RuntimeError(f"Unexpected policy result: {verdict}")
    print(f"Mapped {observed}; allowed {allowed}; {verdict}")


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        check(*sys.argv[1:])
