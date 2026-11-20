"""Run one bounded TShark session. Capture threads never call Tk."""

import os
import re
import shutil
import subprocess  # nosec B404
import threading
import time
from collections import deque
from ipaddress import ip_address
from pathlib import Path

from .stun import parse


def command(local, *, interface=None, pcap=None, duration=120):
    addr = ip_address(local)
    if "%" in str(addr) or addr.is_unspecified or addr.is_multicast:
        raise ValueError("Informe o IP unicast local sem zona")
    if (interface is None) == (pcap is None) or not 1 <= duration <= 3600:
        raise ValueError("Origem ou duração inválida")
    if interface is not None and not re.fullmatch(r"[\w{][\w .:{}()\\-]{0,199}", interface):
        raise ValueError("Use o índice de tshark -D ou um nome de interface válido")
    executable = shutil.which("tshark")
    if not executable and os.name == "nt":
        candidate = (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark/tshark.exe"
        )
        executable = str(candidate) if candidate.is_file() else None
    if not executable:
        raise FileNotFoundError("TShark ausente. Instale Wireshark/TShark e confira o PATH.")
    if pcap is not None:
        path = Path(pcap).resolve(strict=True)
        if not path.is_file():
            raise ValueError("Selecione um arquivo PCAP")
        source = ["-r", str(path)]
    else:
        source = [
            "-p",
            "-i",
            interface,
            "-f",
            f"udp and dst host {addr}",
            "-a",
            f"duration:{duration}",
        ]
    family = "ip" if addr.version == 4 else "ipv6"
    display = f"{family}.dst == {addr} && udp.payload[4:4] == 21:12:a4:42"
    return [executable, "-n", "-l", *source, "-Y", display, "-T", "fields", "-e", "udp.payload"]


def run(args, stop, observe, *, timeout=135):
    """Block until EOF, cancellation or deadline. Reap the child on every path."""
    if stop.is_set():
        return
    errors = deque(maxlen=4)
    failures = []
    finished = threading.Event()
    with subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as child:  # nosec B603

        def read_packets():
            try:
                for line in child.stdout:
                    try:
                        mapping = parse(
                            bytes.fromhex(line.decode("ascii").strip().replace(":", ""))
                        )
                    except (ValueError, UnicodeError):
                        continue
                    if mapping is not None:
                        observe(mapping)
            except Exception as exc:
                failures.append(exc)
            finally:
                finished.set()

        def read_errors():
            while chunk := child.stderr.read(512):
                errors.append(chunk)

        readers = [threading.Thread(target=target) for target in (read_packets, read_errors)]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        try:
            while not stop.is_set():
                if time.monotonic() >= deadline:
                    raise TimeoutError("Tempo máximo do TShark excedido")
                if finished.wait(0.05):
                    if failures:
                        raise RuntimeError("Falha no consumidor da captura") from failures[0]
                    if child.poll() is not None:
                        break
                    stop.wait(0.05)
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
            child.wait()
            for reader in readers:
                reader.join()
        if child.returncode and not stop.is_set():
            detail = b"".join(errors).decode(errors="replace").strip()
            raise RuntimeError(f"TShark ({child.returncode}): {detail}")
