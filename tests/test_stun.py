import unittest
from ipaddress import ip_address

from analyzer.enrichment import assess, baseline
from analyzer.stun import parse
from tests.fixture import DIRECT, EXPECTED, OTHER, VPN


class DecoderTests(unittest.TestCase):
    def test_v4(self):
        result = parse(DIRECT)
        self.assertEqual((str(result.address), result.port), (OTHER, 3478))
        self.assertEqual(result.transaction, "000102030405060708090a0b")

    def test_ipv6_rfc5769_section_2_3(self):
        data = bytes.fromhex(
            "01010018 2112a442 b7e7a701bc34d686fa87dfae "
            "00200014 0002a147 0113a9faa5d3f179bc25f4b5bed2b9d9"
        )
        self.assertEqual(str(parse(data).address), "2001:db8:1234:5678:11:2233:4455:6677")
        self.assertEqual(parse(data).port, 32853)

    def test_padded_unknown_attribute(self):
        packet = (
            DIRECT[:2] + b"\0\x14" + DIRECT[4:20] + bytes.fromhex("8022000161ffffff") + DIRECT[20:]
        )
        self.assertEqual(parse(packet), parse(DIRECT))

    def test_reject_malformed_datagrams(self):
        for packet in [
            b"",
            DIRECT[:-1],
            DIRECT + b"x",
            b"\0\1" + DIRECT[2:],
            DIRECT[:4] + bytes(4) + DIRECT[8:],
            DIRECT[:22] + b"\0\xff" + DIRECT[24:],
            DIRECT[:25] + b"\3" + DIRECT[26:],
            DIRECT[:2] + b"\0\x10" + DIRECT[4:] + bytes.fromhex("00010004"),
        ]:
            with self.subTest(packet=packet):
                self.assertIsNone(parse(packet))

    def test_policy(self):
        expected = baseline(EXPECTED)
        self.assertEqual(assess(parse(VPN).address, expected), "saída prevista")
        self.assertIn("divergência", assess(parse(DIRECT).address, expected))
        self.assertIn("sem referência", assess(ip_address(OTHER), baseline("")))
        with self.assertRaises(ValueError):
            baseline("1.2.3.4 || udp")
