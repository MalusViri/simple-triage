"""Command-line interface for staticprep."""

from __future__ import annotations

import argparse
from pathlib import Path

from staticprep.config import DEFAULT_RULES_DIR
from staticprep.logging_utils import configure_logging
from staticprep.main import analyze_batch, analyze_sample


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(prog="staticprep")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single sample")
    analyze_parser.add_argument("sample", type=Path)
    analyze_parser.add_argument("--output", type=Path, default=Path("output"))
    analyze_parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_DIR)
    analyze_parser.add_argument("--min-string-length", type=int, default=4)
    analyze_parser.add_argument("--skip-yara", action="store_true")
    analyze_parser.add_argument("--skip-pe", action="store_true")
    analyze_parser.add_argument("--skip-strings", action="store_true")
    analyze_parser.add_argument("--verbose", action="store_true")

    batch_parser = subparsers.add_parser("batch", help="Analyze a directory of samples")
    batch_parser.add_argument("input_dir", type=Path)
    batch_parser.add_argument("--output", type=Path, default=Path("output"))
    batch_parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_DIR)
    batch_parser.add_argument("--min-string-length", type=int, default=4)
    batch_parser.add_argument("--recursive", action="store_true")
    batch_parser.add_argument("--skip-yara", action="store_true")
    batch_parser.add_argument("--skip-pe", action="store_true")
    batch_parser.add_argument("--skip-strings", action="store_true")
    batch_parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(getattr(args, "verbose", False))

    if args.command == "analyze":
        analyze_sample(
            sample_path=args.sample,
            output_root=args.output,
            rules_dir=args.rules,
            min_string_length=args.min_string_length,
            skip_yara=args.skip_yara,
            skip_pe=args.skip_pe,
            skip_strings=args.skip_strings,
        )
        return 0

    if args.command == "batch":
        analyze_batch(
            input_dir=args.input_dir,
            output_root=args.output,
            rules_dir=args.rules,
            recursive=args.recursive,
            min_string_length=args.min_string_length,
            skip_yara=args.skip_yara,
            skip_pe=args.skip_pe,
            skip_strings=args.skip_strings,
        )
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
