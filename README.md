# DetectionForge

**AI-assisted detection engineering: turn Sigma rules into platform-native KQL, with MITRE ATT&CK mapping, false-positive analysis, and tuning guidance generated automatically.**

![CI](https://github.com/yusufefil/detection-forge/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Why this exists

Most "AI security tools" hand a problem to a language model and hope. DetectionForge is built on the opposite principle: **use the right tool for each job.**

- **Structured transformation is deterministic.** Converting a Sigma rule into table-aware Microsoft Defender XDR / Sentinel KQL is a solved problem — [pySigma](https://github.com/SigmaHQ/pySigma) does it reliably and reproducibly. An LLM would only introduce hallucination risk here, so the LLM never touches the conversion.
- **Judgement and explanation are where AI earns its place.** Mapping a detection to MITRE ATT&CK, reasoning about realistic false positives, suggesting tuning, and writing the operational documentation a reviewer actually reads — that is the genuinely useful, time-consuming work an LLM accelerates.

That separation is the whole point of the project. It's also why the output is trustworthy enough to drop into a detection-as-code pipeline.

## What it does

Give it a Sigma rule and it produces a complete, review-ready detection package:

1. **Compiles** the rule to KQL for **Microsoft Defender XDR** (table-aware Advanced Hunting) or **Microsoft Sentinel**.
2. **Enriches** it with an LLM: plain-English summary, MITRE ATT&CK technique mapping, known false positives, tuning suggestions, severity rationale, and first investigation steps.
3. **Renders** everything as clean Markdown — ready for a PR, a runbook, or a detection repo.

```
            ┌──────────────┐
Sigma YAML ─▶│ sigma_loader │ (parse + validate)
            └──────┬───────┘
                   │ SigmaCollection
        ┌──────────┴───────────┐
        ▼                       ▼
 ┌──────────────┐        ┌──────────────┐
 │  converter   │        │   enricher   │
 │  (pySigma)   │        │    (LLM)     │
 │ deterministic│        │  judgement   │
 └──────┬───────┘        └──────┬───────┘
        │ KQL                   │ ATT&CK / FP / tuning
        └──────────┬────────────┘
                   ▼
            ┌──────────────┐
            │ doc_generator│ ─▶ Markdown report
            └──────────────┘
```

## Quickstart

```bash
git clone https://github.com/yusufefil/detection-forge.git
cd detection-forge
pip install -e .

# Convert + enrich (offline dry-run by default — no API key needed)
detforge convert examples/powershell_encoded.yml

# Just the KQL, no LLM:
detforge convert examples/powershell_encoded.yml --no-ai
```

### Example: Sigma in, Defender XDR KQL out

The bundled `examples/powershell_encoded.yml` compiles to table-aware Advanced Hunting KQL:

```kql
DeviceProcessEvents
| where FolderPath endswith "\\powershell.exe"
  and (ProcessCommandLine contains "-enc"
       or ProcessCommandLine contains "-EncodedCommand"
       or ProcessCommandLine contains "-e ")
```

Note that the `process_creation` log source was automatically mapped to the
`DeviceProcessEvents` table and `Image`/`CommandLine` to `FolderPath`/`ProcessCommandLine`
— that mapping comes from pySigma's Defender XDR pipeline, not from a model guessing.

With an AI provider configured, the report also includes an ATT&CK table, false
positives, tuning notes, and investigation steps for the same rule.

## Configuration

DetectionForge ships defaulting to a **dry-run** provider, so the full pipeline
(and CI) runs with zero credentials. To enable real enrichment, copy `.env.example`
to `.env` and set a provider. You bring your own key — nothing is hard-coded, and
`.env` is gitignored.

| Provider | `DETFORGE_AI_PROVIDER` | Required env |
|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` |
| Azure OpenAI | `azure` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` |
| Offline | `dryrun` | none |

```bash
pip install -e ".[openai]"      # or ".[anthropic]"
export DETFORGE_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
detforge convert examples/powershell_encoded.yml --out report.md
```

## Detection-as-code

The conversion path is fully deterministic, which makes it CI-friendly. The
included GitHub Actions workflow installs the package and runs the test suite +
a dry-run conversion on every push — so a Sigma change that no longer compiles
fails the build. Point it at your own rule directory to validate detections in
pull requests before they ever reach production.

## Roadmap

DetectionForge is built in phases. Phase 1 (this release) is complete and working.

- [x] **Phase 1** — Sigma → Defender XDR / Sentinel KQL + LLM enrichment + Markdown reports + CI.
- [ ] **Phase 2** — Natural-language → Sigma generation (describe a behaviour, get a draft rule), and live validation of generated KQL against a real Defender/Sentinel workspace via the Microsoft Graph Security API `runHuntingQuery` endpoint.
- [ ] **Phase 3** — Splunk SPL and QRadar AQL targets, plus batch conversion of a rule directory.

### A note on SPL / AQL (and why they're Phase 3)

The pySigma ecosystem is mid-migration: the Kusto backend used here requires
`pysigma>=1.0`, while the current Splunk and QRadar-AQL backends still pin
`pysigma<0.12`. The two cannot coexist in a single virtual environment. Phase 3
will add those targets through isolated converter environments (separate venvs
invoked as subprocesses) rather than forcing an unsupported dependency set —
keeping each backend on the pySigma version it actually supports.

## Project layout

```
src/detection_forge/
├── sigma_loader.py     # parse + validate Sigma YAML (pySigma)
├── converter.py        # Sigma → KQL (Defender XDR / Sentinel pipelines)
├── enricher.py         # LLM enrichment + robust JSON parsing
├── doc_generator.py    # Markdown rendering
├── config.py           # env-driven settings
├── cli.py              # `detforge convert ...`
└── ai/                 # pluggable providers: openai, azure, anthropic, dryrun
examples/               # sample Sigma rule
tests/                  # end-to-end tests (run offline)
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
