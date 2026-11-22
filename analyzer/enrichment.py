"""Local policy assessment. HTTP requests occur only on explicit GUI actions."""

import http.client
import json
from ipaddress import ip_address


def baseline(value):
    return (
        frozenset(ip_address(item.strip()) for item in value.split(","))
        if value.strip()
        else frozenset()
    )


def assess(address, expected):
    if not expected:
        return "observado (sem referência)"
    if address in expected:
        return "saída prevista"
    return "divergência de saída (investigar)"


def _get(host, path):
    connection = http.client.HTTPSConnection(host, timeout=4)
    try:
        connection.request("GET", path, headers={"User-Agent": "WebRTC-STUN-Analyzer/2"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        data = response.read(8193)
        if len(data) > 8192:
            raise ValueError("Resposta excedeu 8 KiB")
        return data.decode("utf-8").strip()
    finally:
        connection.close()


def public_ip():
    return str(ip_address(_get("api64.ipify.org", "/")))


def geo(value):
    address = ip_address(value)
    if not address.is_global or address.is_multicast or "%" in str(address):
        raise ValueError("Geolocalização exige endereço unicast global")
    data = json.loads(_get("ipinfo.io", f"/{address}/json"))
    if not isinstance(data, dict) or data.get("ip") != str(address):
        raise ValueError("Resposta sem IP correspondente")
    return " | ".join(
        " ".join(str(data.get(key) or "—").split())[:100] for key in ("city", "country", "org")
    )
