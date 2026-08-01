"""Deterministic Sigma -> KQL conversion via pySigma's Kusto backend.

Two targets are supported today:

* ``Target.XDR``      -> Microsoft Defender XDR Advanced Hunting (table-aware:
                         ``DeviceProcessEvents``, ``DeviceNetworkEvents``, ...).
* ``Target.SENTINEL`` -> Microsoft Sentinel (Azure Monitor). Sentinel's schema
                         is open, so a target table must be supplied.

SPL (Splunk) and AQL (QRadar) targets are intentionally *not* wired in here yet.
The pySigma backends for those currently pin ``pysigma<0.12`` while the Kusto
backend requires ``pysigma>=1.0``; the two cannot coexist in one environment.
See the roadmap in README.md for how this is handled (isolated converter envs).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.azuremonitor import azure_monitor_pipeline


class Target(str, Enum):
    """Supported conversion targets."""

    XDR = "xdr"
    SENTINEL = "sentinel"


@dataclass
class ConversionResult:
    target: Target
    queries: list[str]

    @property
    def query(self) -> str:
        """The first (usually only) query, as a convenience."""
        return self.queries[0] if self.queries else ""


def convert(
    collection: SigmaCollection,
    target: Target = Target.XDR,
    sentinel_table: str | None = None,
) -> ConversionResult:
    """Convert a Sigma collection to KQL for the chosen target.

    Args:
        collection: a parsed pySigma collection (see ``sigma_loader.load_rule``).
        target: ``Target.XDR`` (default) or ``Target.SENTINEL``.
        sentinel_table: required when ``target`` is ``SENTINEL`` — the Azure
            Monitor table to query (e.g. ``"DeviceProcessEvents"``).

    Returns:
        ConversionResult with one or more KQL strings.
    """
    if target is Target.XDR:
        backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    elif target is Target.SENTINEL:
        if not sentinel_table:
            raise ValueError(
                "Sentinel target requires --sentinel-table (Sentinel's schema is "
                "open, so the target table is not inferable from the Sigma logsource)."
            )
        backend = KustoBackend(
            processing_pipeline=azure_monitor_pipeline(query_table=sentinel_table)
        )
    else:  # pragma: no cover - exhaustive
        raise ValueError(f"Unsupported target: {target}")

    queries = backend.convert(collection)
    return ConversionResult(target=target, queries=list(queries))
