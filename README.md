# KDP-Adapt: SSH Empirical Motivation — Reproducibility Package

An analysis-ready, privacy-reduced release of SSH honeypot interaction **labels**, research scripts,
aggregated statistics, and three empirical figures supporting the observational-motivation subsection
of the KDP-Adapt manuscript.

**Collection infrastructure is intentionally undisclosed.** No public file contains collection IP addresses,
the number of collection endpoints, or endpoint-specific identifiers. All recorded endpoints are replaced
with the same constant **`HP`**. Public session identifiers are freshly assigned `S000001`, etc. and
are **not** hashes or substrings of original identifiers. Source IPs are also removed. The only data made
public are derived event labels, timestamps, pseudonymous sessions, taxonomy metadata, and aggregates.

## What is included

- `data/public/ssh_events_cid_only.csv` — session-linked, CID-only event labels; *no commands, IPs or raw session IDs*.
- `data/public/cid_taxonomy.csv` — classification IDs and their existing MITRE metadata (not original command patterns).
- `data/public/probe_groups.csv` — fixed CID grouping for analysis.
- `data/derived/dataset_summary.json` — public-safe dataset statistics.
- `data/derived/unmatched_breakdown.csv` — reasons for unmatched labels.
- `scripts/analyze.py` — reproduce summary tables and all three figures from public data only.
- `scripts/privacy_audit.py` — check for direct IPs, endpoint indices, original schema identifiers, and unsafe leaks.
- `scripts/build_public_dataset.py` — optional offline redaction script for the **private** intermediate CSV.
- `figures/` and `manuscript/` — validated descriptive figures and sanitized LaTeX excerpt.

## Dataset overview

| Property | Value |
| --- | ---: |
| Collection dates | 2 January–28 August 2025 |
| Recorded sessions | 387 |
| Session-linked events | 378,867 |
| Events with a mapped CID | 627 |
| Unmatched events (coded `SCAN`) | 378,240 |
| Sessions with at least one mapped CID | 339 |
| Distinct observed CIDs | 53 |

**Important interpretation:** `SCAN` is an internal processing code for unmatched records. It does
**not** establish that every such record is a network scan. A recorded event is not necessarily an
attacker command. Event depth must not be equated with command depth, and the dataset does not carry
honeypot responses or support response-conditioned causal conclusions.

## Quick start

```bash
python -m pip install -r requirements.txt
python scripts/analyze.py
python scripts/privacy_audit.py
```

`analyze.py` writes the summary CSV tables to `data/derived/` and redraws the figures to `figures/`.
No private input or network connection is required. The analysis uses only strictly later timestamps
for continuation and unambiguous timestamp ordering for revalidation.

## Disclosure and data limitations

See [DATA_DICTIONARY](docs/DATA_DICTIONARY.md), [METHODOLOGY](docs/METHODOLOGY.md),
[DATA_AVAILABILITY](docs/DATA_AVAILABILITY.md) and [SECURITY](SECURITY.md).

**Do not upload the original CSV, `commands_mitre.db`, raw command text, private analysis CSV,
raw session IDs, credentials, source addresses, or endpoint-specific aggregate tables.** The
repository intentionally contains neither raw collection files nor the original command-match rules.
The supplied CID-only data reproduce descriptive figures but cannot independently validate the
original string-to-CID matching or endpoint/source-level claims.

## Attribution, licensing and publication

The original dataset and analyses were supplied by the project authors. This package is a prepared
publication candidate, **not** evidence of authorization to release operational telemetry.
Obtain project/institutional authorization and decide on appropriate code/data licenses before
making this repository public. No license is conferred by this draft package.
