import unittest
from unittest.mock import patch

from analyzer.enrichment import geo, public_ip


class EnrichmentTests(unittest.TestCase):
    @patch("analyzer.enrichment.http.client.HTTPSConnection")
    def test_https_limits_and_closure(self, factory):
        connection = factory.return_value
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b"198.51.100.7"
        self.assertEqual(public_ip(), "198.51.100.7")
        factory.assert_called_once_with("api64.ipify.org", timeout=4)
        response.read.assert_called_once_with(8193)
        for status, body in [(302, b""), (200, b"x" * 8193), (200, b"invalid")]:
            response.status, response.read.return_value = status, body
            with self.assertRaises(ValueError):
                public_ip()
        self.assertEqual(connection.close.call_count, 4)

    @patch("analyzer.enrichment._get")
    def test_private_ip_stays_local(self, get):
        for value in ["10.0.0.1", "::1", "127.0.0.1/path", "ff02::1"]:
            with self.assertRaises(ValueError):
                geo(value)
        get.assert_not_called()
