"""Command-line interface for DEEPLINKFUZZ."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import SEVERITY_ORDER, fuzz_manifest

EXAMPLES = """
examples:
  # Fuzz a manifest and print a table of findings (exit 1 if any found)
  deeplinkfuzz fuzz AndroidManifest.xml

  # JSON for CI pipelines / piping into jq
  deeplinkfuzz fuzz AndroidManifest.xml --format json | jq '.findings'

  # Only fail the build on high/critical issues
  deeplinkfuzz fuzz AndroidManifest.xml --min-severity high

  # Include components that are not exported (audit mode)
  deeplinkfuzz fuzz AndroidManifest.xml --include-unexported
"""


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _print_table(result: dict) -> None:
    print(f"entry points: {result['entry_point_count']}  "
          f"fuzz cases: {result['fuzz_cases']}  "
          f"findings: {result['finding_count']}")
    sev = result["severity_counts"]
    if sev:
        summary = "  ".join(f"{k}={v}" for k, v in sorted(
            sev.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]]))
        print(f"severity: {summary}")
    findings = result["findings"]
    if not findings:
        print("\nNo injection findings.")
        return
    print()
    header = f"{'SEVERITY':<9} {'CATEGORY':<20} {'COMPONENT':<28} PAYLOAD"
    print(header)
    print("-" * len(header))
    for f in findings:
        comp = f["component"]
        if len(comp) > 27:
            comp = "..." + comp[-24:]
        print(f"{f['severity']:<9} {f['category']:<20} {comp:<28} {f['payload_name']}")
    print("\nrun with --format json to see full URLs and evidence")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=("Enumerate deep links / intents from an Android manifest and "
                     "replay mutated payloads to find injection bugs in exported "
                     "entry points."),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")

    sub = parser.add_subparsers(dest="command")

    pf = sub.add_parser("fuzz", help="fuzz a manifest for deep-link injection bugs",
                        description="Parse a manifest, enumerate exported entry "
                                    "points, and replay mutated deep links.")
    pf.add_argument("manifest", help="path to AndroidManifest.xml ('-' for stdin)")
    pf.add_argument("--include-unexported", action="store_true",
                    help="also audit components that are not exported")
    pf.add_argument("--min-severity", choices=list(SEVERITY_ORDER.keys()),
                    default="info",
                    help="only report findings at or above this severity "
                         "(also gates the non-zero exit code)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "fuzz":
        parser.print_help()
        return 2

    try:
        text = _read_input(args.manifest)
    except OSError as exc:
        print(f"error: cannot read {args.manifest}: {exc}", file=sys.stderr)
        return 2

    try:
        result = fuzz_manifest(
            text,
            include_unexported=args.include_unexported,
            min_severity=args.min_severity,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        _print_table(result)

    # CI gate: non-zero when findings exist at/above the chosen severity.
    return 1 if result["finding_count"] > 0 else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
