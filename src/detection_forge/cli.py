"""Command-line interface for DetectionForge.

Examples:
    detforge convert examples/powershell_encoded.yml
    detforge convert rule.yml --target sentinel --sentinel-table DeviceProcessEvents
    detforge convert rule.yml --out report.md
    detforge convert rule.yml --no-ai          # KQL only, skip the LLM
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from detection_forge import __version__
from detection_forge.ai.base import DryRunProvider, get_provider
from detection_forge.config import load_ai_settings
from detection_forge.converter import Target, convert
from detection_forge.doc_generator import render_markdown
from detection_forge.enricher import enrich
from detection_forge.sigma_loader import load_rule


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detforge",
        description="Convert Sigma rules to KQL and enrich them with an LLM.",
    )
    parser.add_argument("--version", action="version", version=f"DetectionForge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    conv = sub.add_parser("convert", help="Convert and enrich a Sigma rule.")
    conv.add_argument("rule", help="Path to a Sigma rule (.yml).")
    conv.add_argument(
        "--target",
        choices=[t.value for t in Target],
        default=Target.XDR.value,
        help="Conversion target (default: xdr).",
    )
    conv.add_argument(
        "--sentinel-table",
        help="Azure Monitor table name (required for --target sentinel).",
    )
    conv.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip LLM enrichment; emit the query only.",
    )
    conv.add_argument(
        "--out",
        help="Write the Markdown report to this file instead of stdout.",
    )
    return parser


def cmd_convert(args: argparse.Namespace) -> int:
    try:
        rule = load_rule(args.rule)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    target = Target(args.target)
    try:
        result = convert(rule.collection, target=target, sentinel_table=args.sentinel_table)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    query = result.query

    if args.no_ai:
        provider_name = "skipped (--no-ai)"
        from detection_forge.enricher import Enrichment

        enrichment = Enrichment(parse_error="AI enrichment skipped (--no-ai).")
    else:
        settings = load_ai_settings()
        try:
            provider = get_provider(settings)
        except (ValueError, ImportError) as exc:
            print(f"warning: {exc}\nFalling back to dry-run.", file=sys.stderr)
            provider = DryRunProvider()
            settings = settings.__class__(**{**settings.__dict__, "provider": "dryrun"})
        provider_name = settings.provider
        rule_yaml = Path(args.rule).read_text(encoding="utf-8")
        enrichment = enrich(provider, rule, query, target.value, rule_yaml)

    report = render_markdown(rule, query, target.value, enrichment, provider_name)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Wrote report to {args.out}")
    else:
        print(report)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "convert":
        return cmd_convert(args)
    parser.print_help()  # pragma: no cover
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
