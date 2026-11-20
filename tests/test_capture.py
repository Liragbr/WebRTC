import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzer.capture import command, run
from tests.fixture import DIRECT, EXPECTED, LOCAL, OTHER, write


class CaptureTests(unittest.TestCase):
    def test_reject_invalid_inputs(self):
        for value in ("eth0\n-x", "-r", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                command(LOCAL, interface=value)
        with self.assertRaises(ValueError):
            command("1.1.1.1 || udp", interface="1")

    @patch("analyzer.capture.shutil.which", return_value="/usr/bin/tshark")
    def test_live_filter(self, _which):
        args = command(LOCAL, interface="LAN 2")
        self.assertIn("LAN 2", args)
        self.assertIn(f"udp and dst host {LOCAL}", args)
        self.assertIn("-p", args)

    def test_timeout(self):
        with self.assertRaises(TimeoutError):
            run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                threading.Event(),
                self.fail,
                timeout=0.1,
            )

    def test_stop_after_first_event(self):
        stop = threading.Event()
        program = f"import time; print('{DIRECT.hex()}', flush=True); time.sleep(30)"
        run([sys.executable, "-c", program], stop, lambda _: stop.set(), timeout=3)
        self.assertTrue(stop.is_set())

    def test_process_failure_has_diagnostic(self):
        program = "import sys; print('denied', file=sys.stderr); sys.exit(2)"
        with self.assertRaisesRegex(RuntimeError, "denied"):
            run([sys.executable, "-c", program], threading.Event(), self.fail)


@unittest.skipUnless(shutil.which("tshark"), "requires TShark (mandatory in CI)")
class ReplayTests(unittest.TestCase):
    def test_network_policies_and_local_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "controlled.pcap"
            write(path)
            for expected, verdicts in [
                ("", ["sem referência", "sem referência"]),
                (EXPECTED, ["saída prevista", "divergência"]),
                (f"{EXPECTED},{OTHER}", ["saída prevista", "saída prevista"]),
                (OTHER, ["divergência", "saída prevista"]),
            ]:
                with self.subTest(expected=expected):
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "analyzer.replay",
                            str(path),
                            "--local",
                            LOCAL,
                            "--expected",
                            expected,
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                        timeout=15,
                    )
                    lines = result.stdout.splitlines()
                    self.assertEqual(len(lines), 2)
                    for line, address, verdict in zip(
                        lines, [EXPECTED, OTHER], verdicts, strict=True
                    ):
                        self.assertIn(address, line)
                        self.assertIn(verdict, line)
