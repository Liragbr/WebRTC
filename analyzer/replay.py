"""Replay a controlled capture without a display or network access."""

import argparse
import sys
from threading import Event

from .capture import command, run
from .enrichment import assess, baseline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--local", required=True)
    parser.add_argument("--expected", default="")
    args = parser.parse_args()
    try:
        expected = baseline(args.expected)

        def report(mapping):
            print(
                mapping.transaction,
                mapping.address,
                mapping.port,
                assess(mapping.address, expected),
            )

        run(command(args.local, pcap=args.pcap), Event(), report)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    sys.exit(main())
