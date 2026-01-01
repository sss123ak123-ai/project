"""
Entry point for the AI-assisted web vulnerability analysis framework.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.orchestrator import Orchestrator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ethical AI-assisted web vulnerability analysis tool."
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional path to write a single consolidated JSON report.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    orchestrator = Orchestrator(args.config)
    serialized_results = orchestrator.run()

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump([json.loads(item) for item in serialized_results], handle, indent=2)

    for item in serialized_results:
        print(item)


if __name__ == "__main__":
    main()
