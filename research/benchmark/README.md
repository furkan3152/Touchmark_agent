# Touchmark ground-truth benchmark

Six small Stellar agents, one per language, with planted defects and decoys whose
exact locations are recorded in `labels/`. Use it to measure whether the Touchmark
audit is:

- **precise**: its findings are real. Every agent has decoys: code a pattern
  scanner would flag (`Keypair.fromSecret`, `sign()`, `submitTransaction`, a
  file read, a fetch, "secret" variable names, a paying route) that is actually
  safe because an enforcing control exists. At least one decoy per agent has its
  control in a different file from the sink, so the auditor has to trace across
  files.
- **complete**: it finds the planted defects (recall, and recall on high/critical).
- **consistent**: re-running the audit on the same agent finds the same defects.
- **language-independent**: recall and precision hold across Python, TypeScript,
  Go, Java, Kotlin and C#.

| agent | language | stack | defects | decoys |
| --- | --- | --- | --- | --- |
| `invoice-settler` | Python | FastAPI, stellar-sdk | 3 | 3 |
| `treasury-mcp` | TypeScript | MCP server, @stellar/stellar-sdk | 3 | 2 |
| `payout-relay` | Go | net/http, github.com/stellar/go (mostly clean) | 1 | 3 |
| `escrow-agent` | Java | Spring Boot, java-stellar-sdk | 4 | 3 |
| `swap-desk` | Kotlin | Ktor, java-stellar-sdk | 3 | 2 |
| `payroll-agent` | C# | ASP.NET minimal API, stellar-dotnet-sdk | 3 | 2 |

Defect categories are the keys of `CATEGORIES` in `backend/app/services/deep_review.py`.

## Layout

```
research/benchmark/
  agents/<name>/        the code that is audited (README, manifest, sources)
  labels/<name>.json    ground truth for that agent
  labels/build_labels.py regenerates the label files from text anchors
  score.py              scores report JSON files against the labels
```

**Rule: labels must never be placed inside an agent folder.** The auditor is given
only `agents/<name>/`; anything in there (label files, notes, comments naming a
defect or saying code is safe) leaks the answer and invalidates the run. Source
comments in the agents must read like a normal codebase's. `score.py --selftest`
fails if a label-like JSON file appears inside an agent folder.

## Label format

```json
{"agent": "invoice-settler", "language": "python",
 "defects": [{"id": "PY-D1", "category": "unauthorized_payment", "severity": "critical",
              "file": "app/main.py", "line_start": 62, "line_end": 67, "summary": "...",
              "accept_categories": ["control_bypass", "economic_loss"],
              "alt_locations": [{"file": "app/ledger.py", "line_start": 46, "line_end": 47}]}],
 "decoys": [{"id": "PY-K2", "file": "app/ledger.py", "line_start": 24, "line_end": 26,
             "why_safe": "...", "control_file": "app/policy.py", "control_line": 39}]}
```

`file` is relative to the agent folder. `alt_locations` (optional) lists other lines
where a correct finding for a defect that spans files may point. Line numbers are
computed by `labels/build_labels.py`; after editing any agent source, run
`python3 labels/build_labels.py` and commit the regenerated JSON. Do not edit line
numbers by hand.

## Running

1. Audit each agent folder with the Touchmark live demo, using a GitHub reference
   to the folder, for example
   `https://github.com/furkan3152/Touchmark_agent/tree/main/research/benchmark/agents/invoice-settler`.
   Use the same tier and settings for every agent.
2. Save the report JSON (the downloaded report, or the job result that nests it
   under `report`) as e.g. `results/<date>/invoice-settler-run1.json`. For
   consistency, audit each agent at least three times and save every run.
3. Score:

```bash
python3 research/benchmark/score.py --labels research/benchmark/labels results/<date>/*.json
python3 research/benchmark/score.py --labels research/benchmark/labels --markdown results/<date>/*.json
python3 research/benchmark/score.py --selftest
```

The agent for a report is inferred from paths in the evidence
(`research/benchmark/agents/<name>/...`), then from the report body, then from
the file name; pass `--agent <name>` to force it.

## Matching rules

- Findings are read from the report's `findings` list. Only risk findings count
  (`is_risk` true, or `kind` absent or `risk`); evidence gaps and warnings are ignored.
- Every `path:line` (or `path:start-end`) in a finding's `evidence` (and `file`/`line`
  fields when present) is a cited location. Paths are normalised: anything up to and
  including `research/benchmark/agents/<name>/` is dropped, and a bare file name
  matches a labelled path that ends with it.
- A cited location matches a labelled range when it falls within
  `line_start - 5 .. line_end + 5` in the same file. If several ranges qualify, the
  nearest wins and ties go to the defect.
- A finding that matches any defect location is **matched** (a finding may find more
  than one defect). Category agreement (finding category, from the `category` field or
  the deep-review id `<dimension>-ai-<category>-<n>`, equals the label category or one
  of `accept_categories`) is reported separately and is not needed for a match.
- A finding that matches only decoys is a **decoy false positive**.
- Any other risk finding of severity medium or above is **unlabelled**: listed for
  manual triage, not counted as a false positive. If triage shows it is real, add it to
  the labels as a defect (via `build_labels.py`).

## Metrics

Per report, per agent (all runs) and overall:

- `recall` = defects found / defects
- `recall_high` = high and critical defects found / high and critical defects
- `decoy_fp_rate` = decoys hit / decoys
- `precision_lower_bound` = matched findings / (matched findings + decoy false positives)
- `category_agreement` = matched (finding, defect) pairs whose category agrees
- `unlabelled_count`

With several reports for one agent, `consistency` gives the mean pairwise Jaccard of
the found defect sets, the Jaccard of always-found over ever-found, and the defects
found in some runs but not others (`unstable`).

Comparing recall and precision across the six agents gives the language view: the
defect classes are deliberately repeated across languages (signing external input,
replay or double execution, missing authorization, protocol misuse, secrets).
