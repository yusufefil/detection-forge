"""Load and validate Sigma rules.

Wraps pySigma's :class:`SigmaCollection` and pulls out the metadata we care
about for documentation (title, level, description, ATT&CK tags, log source).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection


@dataclass
class SigmaRule:
    """A parsed Sigma rule plus the metadata we surface in reports."""

    title: str
    description: str
    level: str
    status: str
    logsource: dict
    tags: list[str] = field(default_factory=list)
    rule_id: str | None = None
    author: str | None = None
    raw: dict = field(default_factory=dict)
    collection: SigmaCollection | None = None

    @property
    def attack_tags(self) -> list[str]:
        """Return the ATT&CK technique tags declared in the rule (e.g. t1059.001)."""
        return [t for t in self.tags if t.lower().startswith("attack.t")]


def load_rule(path: str | Path) -> SigmaRule:
    """Parse a single Sigma rule from a YAML file.

    Raises:
        FileNotFoundError: if the path does not exist.
        ValueError: if the YAML is not a valid Sigma rule.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Sigma rule not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(doc, dict) or "detection" not in doc:
        raise ValueError(
            f"{path} does not look like a Sigma rule (missing 'detection' block)."
        )

    # Let pySigma do the real validation/parsing.
    collection = SigmaCollection.from_yaml(text)

    return SigmaRule(
        title=doc.get("title", "Untitled rule"),
        description=doc.get("description", ""),
        level=str(doc.get("level", "medium")),
        status=str(doc.get("status", "experimental")),
        logsource=doc.get("logsource", {}) or {},
        tags=[str(t) for t in (doc.get("tags") or [])],
        rule_id=doc.get("id"),
        author=doc.get("author"),
        raw=doc,
        collection=collection,
    )
