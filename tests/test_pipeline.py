"""End-to-end tests that run with no credentials (AI provider = dryrun).

These are what CI executes: they prove the deterministic conversion path and
the full pipeline wiring without ever calling an external model.
"""

from pathlib import Path

import pytest

from detection_forge.ai.base import DryRunProvider
from detection_forge.converter import Target, convert
from detection_forge.doc_generator import render_markdown
from detection_forge.enricher import enrich
from detection_forge.sigma_loader import load_rule

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "powershell_encoded.yml"


def test_loader_reads_metadata():
    rule = load_rule(EXAMPLE)
    assert rule.title == "Suspicious PowerShell Encoded Command"
    assert rule.level == "high"
    assert "attack.t1059.001" in [t.lower() for t in rule.tags]
    assert rule.attack_tags  # at least one attack.t* tag


def test_loader_rejects_non_sigma(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: not a rule\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_rule(bad)


def test_xdr_conversion_is_table_aware():
    rule = load_rule(EXAMPLE)
    result = convert(rule.collection, target=Target.XDR)
    query = result.query
    # The XDR pipeline maps process_creation -> DeviceProcessEvents.
    assert "DeviceProcessEvents" in query
    assert "ProcessCommandLine" in query


def test_sentinel_requires_table():
    rule = load_rule(EXAMPLE)
    with pytest.raises(ValueError):
        convert(rule.collection, target=Target.SENTINEL)


def test_dryrun_enrichment_and_render():
    rule = load_rule(EXAMPLE)
    result = convert(rule.collection, target=Target.XDR)
    enrichment = enrich(
        DryRunProvider(), rule, result.query, "xdr", EXAMPLE.read_text(encoding="utf-8")
    )
    assert enrichment.parse_error is None  # dryrun returns valid JSON
    md = render_markdown(rule, result.query, "xdr", enrichment, "dryrun")
    assert md.startswith("# Suspicious PowerShell Encoded Command")
    assert "```kql" in md
