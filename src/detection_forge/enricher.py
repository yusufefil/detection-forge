"""LLM enrichment of a detection rule.

Given a Sigma rule and its compiled KQL, ask the model for the things a human
detection engineer would write in a rule's documentation: a plain-English
summary, MITRE ATT&CK technique mapping, likely false positives, tuning
suggestions, a severity rationale, and first investigation steps.

The model is instructed to return a single JSON object; we parse it defensively
(stripping code fences, tolerating leading/trailing prose) and never crash the
pipeline on a malformed response.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from detection_forge.ai.base import AIProvider
from detection_forge.sigma_loader import SigmaRule

_SYSTEM = (
    "You are a senior detection engineer. You map detections to MITRE ATT&CK and "
    "write concise, accurate operational documentation. You respond with a single "
    "JSON object and nothing else — no markdown, no commentary."
)

_USER_TEMPLATE = """\
Analyze this detection rule and return a JSON object with EXACTLY these keys:

- "summary": string. 2-3 sentences: what behaviour this detects and why it matters.
- "attack": array of objects, each {{"id","name","tactic"}}. The ATT&CK techniques
  this rule covers. Prefer sub-techniques (e.g. T1059.001) when applicable.
- "false_positives": array of strings. Realistic benign activity that could trigger this.
- "tuning": array of strings. Concrete suggestions to reduce noise (exclusions, scoping).
- "severity_rationale": string. One sentence justifying the rule's severity.
- "investigation_steps": array of strings. The first 3-5 steps an analyst should take.

Return ONLY the JSON object.

== Sigma rule (YAML) ==
{rule_yaml}

== Compiled query ({target}) ==
{query}
"""


@dataclass
class AttackTechnique:
    id: str
    name: str
    tactic: str


@dataclass
class Enrichment:
    summary: str = ""
    attack: list[AttackTechnique] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    tuning: list[str] = field(default_factory=list)
    severity_rationale: str = ""
    investigation_steps: list[str] = field(default_factory=list)
    parse_error: str | None = None
    raw: str = ""


def enrich(
    provider: AIProvider,
    rule: SigmaRule,
    query: str,
    target: str,
    rule_yaml: str,
) -> Enrichment:
    """Run the rule + query through the LLM and return a structured Enrichment."""
    user = _USER_TEMPLATE.format(rule_yaml=rule_yaml, target=target, query=query)
    raw = provider.complete(_SYSTEM, user)
    return _parse(raw)


def _parse(raw: str) -> Enrichment:
    """Parse the model's text into an Enrichment, tolerating common noise."""
    payload = _extract_json(raw)
    if payload is None:
        return Enrichment(parse_error="Could not locate a JSON object in response.", raw=raw)
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return Enrichment(parse_error=f"JSON decode failed: {exc}", raw=raw)

    techniques = []
    for item in data.get("attack", []) or []:
        if isinstance(item, dict):
            techniques.append(
                AttackTechnique(
                    id=str(item.get("id", "")),
                    name=str(item.get("name", "")),
                    tactic=str(item.get("tactic", "")),
                )
            )

    return Enrichment(
        summary=str(data.get("summary", "")),
        attack=techniques,
        false_positives=[str(x) for x in (data.get("false_positives") or [])],
        tuning=[str(x) for x in (data.get("tuning") or [])],
        severity_rationale=str(data.get("severity_rationale", "")),
        investigation_steps=[str(x) for x in (data.get("investigation_steps") or [])],
        raw=raw,
    )


def _extract_json(text: str) -> str | None:
    """Pull the first balanced ``{...}`` block out of arbitrary model text."""
    text = text.strip()
    if text.startswith("```"):
        # strip a leading ```json / ``` fence and trailing fence
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
        if text.lstrip().startswith("json"):
            text = text.lstrip()[4:]
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None
