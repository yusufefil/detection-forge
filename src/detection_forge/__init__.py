"""DetectionForge — AI-assisted detection engineering toolkit.

Convert Sigma rules into platform-native detections (Microsoft Defender XDR /
Sentinel KQL) and enrich them with an LLM: plain-English explanation,
MITRE ATT&CK mapping, false-positive analysis, and tuning guidance.

The deterministic Sigma -> KQL conversion is handled by pySigma. The LLM is
used only where it adds genuine value (explanation, ATT&CK reasoning, FP/tuning
notes, and — on the roadmap — natural-language -> Sigma generation). This split
is deliberate: structured transforms belong to a parser, not a language model.
"""

__version__ = "0.1.0"

from detection_forge.sigma_loader import load_rule, SigmaRule
from detection_forge.converter import convert, Target
from detection_forge.enricher import enrich, Enrichment

__all__ = [
    "load_rule",
    "SigmaRule",
    "convert",
    "Target",
    "enrich",
    "Enrichment",
    "__version__",
]
