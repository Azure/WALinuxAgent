---
name: dag-generation
description: "Generate DAG (Docs-Augmented Generation) documentation for any codebase from astred compose summaries. Runs a multi-step pipeline: extract symbols, cluster by namespace, label with LLM, create intermediate + final DAG docs, generate L0 primer and indexes. Use when: generate DAG docs, create copilot docs, generate codebase documentation, run DAG pipeline, create docs-augmented generation, build agent-optimized docs, generate L0 primer, update DAGs from git diff, incremental DAG update."
argument-hint: "Describe what you want: full pipeline, specific step, or incremental update"
---

# DAG Documentation Generation Pipeline

Generate agent-optimized DAG (Docs-Augmented Generation) documentation for any codebase from astred compose summaries. The pipeline clusters source files by namespace, labels them with an LLM, and produces layered documentation (L1-conceptual, L2-platform, L3-flows) plus an L0 foundation primer.

## When to Use

- Generate DAG documentation for a new codebase
- Re-run the full pipeline after major refactoring
- Run a specific pipeline step (e.g., re-label clusters, regenerate L0)
- Incrementally update DAGs after source code changes (git diff based)
- Understand what each pipeline step does

## Prerequisites

1. **Python 3.10+** in the repo's virtual environment
2. **`agency` CLI** installed and authenticated (`agency copilot` must work)
3. **Astred compose summaries** already generated at `{REPO_ROOT}/.compose/summaries/src/` (from `--embed none`) or `{REPO_ROOT}/.astred/compose/summaries/{REPO_NAME}/src/` (from `--embed all`). The pipeline auto-detects both locations.
4. Pipeline scripts present in `scripts/dag-enrichment/`

Verify prerequisites:
```bash
python --version        # 3.10+
agency copilot --help   # must respond
ls .compose/summaries/src/   # or ls .astred/compose/summaries/
```

> **⚠️ Run the LLM steps in a plain shell, NOT from inside an active agent
> session.** The LLM steps (2, 4, 5, 6) shell out to `agency copilot` and block
> on it. If this skill is itself executed from within an already-running agent
> session, that nested `agency copilot` call re-enters the **same** session
> instead of launching an isolated sub-agent — the parent Python process
> deadlocks (it is blocked in `subprocess.run` waiting for a child that can only
> progress once the host turn ends). See
> [Known Issue: nested `agency copilot` re-entrancy](#known-issue-nested-agency-copilot-re-entrancy--exit--1-false-artifact)
> below before running.

## Pipeline Overview

The pipeline has two phases: **Generation** (steps 0–6, run once / on major
refactors) and **Enrichment** (steps 7–8, deterministic, re-run on every DAG
regeneration to keep the routing table and tier-2 pointers fresh).

```
Generation (steps 0–6):
  Step 0 ─→ Step 1 ─→ Step 2 ─→ Step 3 ─→ Step 4 ─→ Step 5 ─→ Step 6
  Extract    Cluster   Label     Generate   Create     Gen L0+    Gen Copilot
  Symbols    by NS     Clusters  Mapping    DAG Docs   Indexes    Instructions
  (Python)   (Python)  (LLM)     (Python)   (LLM)      (LLM)      (LLM)
  ~10s       ~5s       ~5-15min  ~5s        ~30-60min  ~5min      ~1min

Enrichment (steps 7–8, deterministic — no LLM, idempotent, re-run every regen):
  Step 7 ─→ Step 8
  Inject     Inject
  Routing    Tier-2
  Table      Pointers
  (Python)   (Python)
  ~2s        ~2s
```

| Step | Script | LLM? | Output |
|------|--------|------|--------|
| 0 | [step0_extract_symbols.py](../../../scripts/dag-enrichment/step0_extract_symbols.py) | No | `output/clustering/symbols/file_metadata.json` |
| 1 | [step1_namespace_clustering.py](../../../scripts/dag-enrichment/step1_namespace_clustering.py) | No | `output/clustering/symbols/cluster_details.json` |
| 2 | [step2_label_clusters.py](../../../scripts/dag-enrichment/step2_label_clusters.py) | Yes | `output/clustering/symbols/cluster_labels.json` |
| 3 | [step3_generate_mapping.py](../../../scripts/dag-enrichment/step3_generate_mapping.py) | No | `compose_to_dag_mapping-symbols.json` |
| 4 | [create_dags_from_mapping.py](../../../scripts/dag-enrichment/create_dags_from_mapping.py) | Yes | `intermediate-docs/` + `copilot-docs/` |
| 5 | [generate_indexes_and_l0.py](../../../scripts/dag-enrichment/generate_indexes_and_l0.py) | Yes | `copilot-docs/L0-foundations/`, `docs-index.md` |
| 6 | [step6_generate_copilot_instructions.py](../../../scripts/dag-enrichment/step6_generate_copilot_instructions.py) | Yes | `.github/copilot-instructions.md` (or `copilot-instructions-dag.md`) |
| 7 | [step7_inject_routing_table.py](../../../scripts/dag-enrichment/step7_inject_routing_table.py) | No | `.github/copilot-instructions.md` — auto-generated Component Mapping table |
| 8 | [step8_inject_tier2_pointer.py](../../../scripts/dag-enrichment/step8_inject_tier2_pointer.py) | No | `copilot-docs/**/*.md` — tier-2 pointer banners |

Shared utility: [dag_utils.py](../../../scripts/dag-enrichment/dag_utils.py) — auto-detects compose summaries path
Incremental updates: [update_dags.py](../../../scripts/dag-enrichment/update_dags.py) — git-diff-based DAG updates

All step scripts are committed under `scripts/dag-enrichment/`.

## Procedure: Full Pipeline

Run from the **repo root** (`cd {REPO_ROOT}`). Each step is idempotent — safe to re-run.

### Step 0: Extract Symbols

Parses compose summaries, extracts namespaces and symbols per source file.

```bash
python scripts/dag-enrichment/step0_extract_symbols.py
```

- Auto-detects compose summaries path (override: `--compose-base <path>`)
- Processes `.cs.md`, `.c.md`, `.cpp.md` files
- Output: `scripts/dag-enrichment/output/clustering/symbols/`

### Step 1: Cluster by Namespace

Groups files by defining namespace. Small clusters merge into parent namespaces.

```bash
python scripts/dag-enrichment/step1_namespace_clustering.py --min-cluster-size 2
```

| Flag | Default | Description |
|------|---------|-------------|
| `--min-cluster-size` | `2` | Clusters smaller than this merge into parent. Use `2` for ~174 clusters, `5` for ~72. |

### Step 2: Label Clusters (LLM)

Calls LLM in batches to assign each cluster a filename, description, and layer (L1/L2/L3).

```bash
python scripts/dag-enrichment/step2_label_clusters.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--approach` | `symbols` | Clustering approach to read from |
| `--batch-size` | `15` | Clusters per LLM call |

### Step 3: Generate Mapping JSON

Combines cluster labels into `compose_to_dag_mapping-symbols.json`.

```bash
python scripts/dag-enrichment/step3_generate_mapping.py
```

### Step 4: Create DAG Documents (LLM)

Main doc generation — creates intermediate DAGs (raw grouped content) then distills final DAGs (~200 lines each).

```bash
python scripts/dag-enrichment/create_dags_from_mapping.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mapping` | `compose_to_dag_mapping-symbols.json` | Mapping JSON |
| `--intermediate-dir` | `intermediate-docs/` | Output for intermediate DAGs |
| `--final-dir` | `copilot-docs/` | Output for final DAGs |
| `--compose-base` | auto-detect | Compose summaries path |
| `--max-parallel` | `4` | Concurrent LLM subagents |
| `--intermediate-only` | — | Only create intermediates |
| `--final-only` | — | Only distill finals from existing intermediates |
| `--template-final-dir` | — | Existing final DAGs as format templates |

### Step 5: Generate L0 Primer and Indexes (LLM)

Generates L0 foundation primer, master docs-index, and per-layer indexes via LLM.

```bash
python scripts/dag-enrichment/generate_indexes_and_l0.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dag-dir` | `copilot-docs/` | Root of final DAGs |
| `--intermediate-dir` | — | Intermediate DAGs for fallback references |

### Step 6: Generate `.github/copilot-instructions.md` (LLM)

Synthesizes a repo-specific `copilot-instructions.md` from the L0 primer, master
`docs-index.md`, and per-layer indexes produced by Step 5. The output describes
the codebase, links the DAG docs, defines hard rules for AI agents, and lists
best-effort build/test commands derived from detected build files.

```bash
python scripts/dag-enrichment/step6_generate_copilot_instructions.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dag-dir` | `copilot-docs/` | Root of final DAGs (Step 5 output) |
| `--github-dir` | `.github/` | Output `.github` directory |
| `--force-suffix` | — | Always write `copilot-instructions-dag.md` instead of `copilot-instructions.md` |

**Output filename rule** — If `.github/copilot-instructions.md` already exists,
the script writes to `.github/copilot-instructions-dag.md` to avoid overwriting
user-authored instructions. Otherwise it writes to `.github/copilot-instructions.md`.
Use `--force-suffix` to always pick the `-dag.md` variant.

### Step 7: Inject the Component Mapping routing table (deterministic)

Turns the mapping JSON from Step 3 into a deterministic **Component Mapping**
table and writes it into a marker-bounded section of
`.github/copilot-instructions.md`. The table gives agents three lookups — by
source path, by class/symbol, and by concept — each resolving to a tier-1 ->
tier-2 reading chain, so the agent jumps straight to the right doc instead of
exploring with `list_dir`.

```bash
python scripts/dag-enrichment/step7_inject_routing_table.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mapping` | `scripts/dag-enrichment/compose_to_dag_mapping-symbols.json` | Mapping JSON from Step 3 |
| `--instructions` | `.github/copilot-instructions.md` | Target instructions file |

- **Idempotent** — only the content between
  `<!-- AUTO-GENERATED-MAPPING:BEGIN ... -->` and `<!-- AUTO-GENERATED-MAPPING:END -->`
  is rewritten; everything else in the file is preserved. First run inserts the
  block just before the `## Hard Rules` anchor (or appends if absent).
- **Deterministic** — no LLM. Complements Step 6: run Step 6 once to bootstrap
  the instructions, then Step 7 on every regeneration to refresh the table.

### Step 8: Inject tier-2 pointer banners (deterministic)

Inserts a short banner right after the H1 of every tier-1
`copilot-docs/{layer}/{name}.md` that has a matching
`intermediate-docs/{layer}/{name}.content.md` companion. The banner tells the
agent (and human readers) to escalate to the tier-2 companion for any
implementation detail — a named class / method / error code / config key / flow
step — and how to read the (often large) companion **surgically**: grep for the
target `.cs` section, range-read only that block, and start with its *Purpose
and Functionality* sub-section.

```bash
python scripts/dag-enrichment/step8_inject_tier2_pointer.py

# Preview which docs would change without writing:
python scripts/dag-enrichment/step8_inject_tier2_pointer.py --dry-run
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | — | Report which tier-1 docs would get / refresh the banner, without writing |

- **Idempotent** — the banner lives between
  `<!-- TIER2-POINTER:BEGIN ... -->` and `<!-- TIER2-POINTER:END -->`; re-runs
  replace it in place. Tier-1 docs **without** a tier-2 companion (e.g.
  `docs-index.md` navigation stubs) are skipped.
- **Deterministic** — no LLM. Run on every regeneration so banners track the
  current set of tier-2 companions.

### Manual enrichment of `copilot-instructions.md` (one-time, hand-authored)

Steps 6–8 produce the machine-managed parts of `copilot-instructions.md` (the
LLM-bootstrapped body, the auto-generated Component Mapping, and the tier-1
banners). On top of those, the file carries **hand-authored navigation guidance**
that the benchmark proved materially improves agent answer quality. These live
*outside* the auto-generated markers and are preserved across regenerations:

- **Context resolution order** — docs-index first (always), then tier-1, then the
  tier-2 `.content.md` companion *when the question needs detail*, then targeted
  source to verify.
- **Altitude-aware escalation** — open tier-2 for detail questions (a named
  class / method / field / error code / config key / flow step / platform
  difference); **stay at tier-1** for high-level / overview / "without source"
  questions. Over-reading is penalised as much as under-reading.
- **"Reading a tier-2 `.content.md` efficiently"** — these docs concatenate one
  `## <source/path>.cs` section per file and can exceed 100 KB; grep for the
  target `.cs` section, range-read only that block, start with *Purpose and
  Functionality*, and escalate into *Key Components* / *Interactions* only when
  needed.
- **Self-check before answering** — (1) did I start at `docs-index.md`?
  (2) does my reading depth match the question's altitude? (3) did I finish
  every part the question asked for?

The same guidance is mirrored in `AGENTS.md` and
`.github/agents/dag-explorer.agent.md` so every agent surface gets it. When
bootstrapping a brand-new repo with Step 6, port these sections over (they are
repo-agnostic) and keep them outside the `AUTO-GENERATED-MAPPING` markers.

## Procedure: Quick Start (Copy-Paste)

```bash
cd {REPO_ROOT}
python scripts/dag-enrichment/step0_extract_symbols.py
python scripts/dag-enrichment/step1_namespace_clustering.py
python scripts/dag-enrichment/step2_label_clusters.py
python scripts/dag-enrichment/step3_generate_mapping.py
python scripts/dag-enrichment/create_dags_from_mapping.py
python scripts/dag-enrichment/generate_indexes_and_l0.py
python scripts/dag-enrichment/step6_generate_copilot_instructions.py
python scripts/dag-enrichment/step7_inject_routing_table.py
python scripts/dag-enrichment/step8_inject_tier2_pointer.py
```

Total time: ~40-80 minutes (most spent in LLM calls at steps 2 and 4; steps
7–8 are deterministic and finish in seconds).

## Procedure: Incremental Updates (Git-Diff)

After initial DAG creation, keep DAGs in sync with source code changes without re-running the full pipeline.

### One-Time Setup

```bash
python scripts/dag-enrichment/update_dags.py --init
```

### Running Updates

```bash
# Default: full-resync (re-synthesize affected final DAGs)
python scripts/dag-enrichment/update_dags.py

# Cheaper: patch mode (LLM patches existing finals from diff)
python scripts/dag-enrichment/update_dags.py --mode patch

# Preview without modifying
python scripts/dag-enrichment/update_dags.py --dry-run

# Force update all affected (skip significance check)
python scripts/dag-enrichment/update_dags.py --force
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `full-resync` | `full-resync` or `patch` |
| `--max-parallel` | `4` | Concurrent LLM calls |
| `--src-prefix` | `src/` | Source directory prefix in git paths |
| `--dry-run` | — | Show plan without executing |
| `--force` | — | Skip significance check |

### Re-run Only Final DAGs

If intermediates are correct but finals need re-generation:
```bash
python scripts/dag-enrichment/create_dags_from_mapping.py --final-only
```

## Output Structure

```
{REPO_ROOT}/
├── .github/
│   └── copilot-instructions.md            # Step 6 output (or copilot-instructions-dag.md
│                                          #   if copilot-instructions.md already existed).
│                                          #   Step 7 injects the AUTO-GENERATED-MAPPING
│                                          #   Component Mapping table into it.
├── copilot-docs/                          # Final DAGs (each tier-1 doc carries a Step 8
│                                          #   TIER2-POINTER banner after its H1)
│   ├── L0-foundations/codebase-primer.md   # L0 primer (LLM-generated)
│   ├── L1-conceptual/                     # Architecture docs
│   │   ├── docs-index.md
│   │   └── *.md
│   ├── L2-platform/                       # Infrastructure docs
│   │   ├── docs-index.md
│   │   └── *.md
│   ├── L3-flows/                          # Workflow docs
│   │   ├── docs-index.md
│   │   └── *.md
│   └── docs-index.md                      # Master index
├── intermediate-docs/                     # Intermediate DAGs (for incremental updates)
│   ├── L1-conceptual/*.content.md
│   ├── L2-platform/*.content.md
│   └── L3-flows/*.content.md
└── .dag-state.json                        # Git hash tracker (for incremental updates)
```

## Layer Classification

| Layer | Question | Contents |
|-------|----------|----------|
| **L1-conceptual** | "What is it?" | Core architecture, interfaces, contracts, abstract patterns |
| **L2-platform** | "How does it work?" | Infrastructure, utilities, config, diagnostics, ALL tests |
| **L3-flows** | "How to do it?" | End-to-end workflows, orchestration sequences |

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| `No compose summaries found` | Run astred compose first, or pass `--compose-base <path>` |
| `agency copilot` not found | Install and authenticate the agency CLI |
| Final DAGs have content loss | Use `create_dags_from_mapping.py --final-only` to regenerate |
| New files not in DAGs | Run full pipeline (steps 0–6) to re-cluster |
| `DAGs already at <hash>` | Edit `.dag-state.json` to set `last_updated_hash` back |
| `copilot-instructions-dag.md` written instead of primary | Expected — `.github/copilot-instructions.md` already existed. Diff the two and merge manually, or delete the primary and re-run Step 6. |
| Step 6 wrote a minimal fallback | DAG context (L0 primer, indexes) was missing. Run Step 5 (`generate_indexes_and_l0.py`) first. |
| Component Mapping table missing/stale in `copilot-instructions.md` | Run Step 7 (`step7_inject_routing_table.py`). It only rewrites the `AUTO-GENERATED-MAPPING` block; hand-authored guidance is preserved. |
| Tier-2 pointer banners missing/stale in tier-1 docs | Run Step 8 (`step8_inject_tier2_pointer.py`). Use `--dry-run` first to preview. Docs with no tier-2 companion are skipped by design. |
| LLM step exits with **`-1` and empty stdout** (steps 2/4/5/6) | Almost always the nested-`agency` re-entrancy deadlock — **not** a real failure. See [Known Issue](#known-issue-nested-agency-copilot-re-entrancy--exit--1-false-artifact) below. Verify the step's on-disk **artifact** (not the exit code); if the artifact is present and valid, treat the `-1` as noise and continue. |

## Known Issue: nested `agency copilot` re-entrancy / exit `-1` false artifact

**Symptom.** While running an LLM step (Step 2 label clusters, Step 4 create DAGs,
Step 5 L0 + indexes, Step 6 copilot-instructions) the step process is terminated
and PowerShell reports **exit code `-1` with empty captured stdout**. You may also
see the current agent session suddenly receive injected, user-style turns such as:

> *"Read the file …/_label_prompt_batch0.txt and follow its instructions exactly.
> Write ONLY the JSON array output to …/_label_result_batch0.txt. No markdown fences."*

**Root cause — the LLM steps assume `agency copilot` launches an *isolated*
sub-agent.** Each LLM step writes a prompt file and then does a **blocking**
call, e.g. (from `step2_label_clusters.py`):

```python
subprocess.run(["agency", "copilot", "-p",
                f"Read {prompt_file} ... write ONLY the output to {result_file} ...",
                "--no-default-mcps"],
               capture_output=True, timeout=...)   # <-- blocks here
```

When the skill is run **from inside an already-active agent session**, that nested
`agency copilot` call is routed back into the **same** session rather than a fresh,
sandboxed agent. This creates a deadlock:

1. The parent Python process is blocked in `subprocess.run(...)`.
2. Its `agency` child can only make progress if the **host** turn ends and writes
   the expected `result_file`.
3. When the next turn / tool call arrives, the runtime tears down the blocked
   process tree. A process killed by termination (rather than exiting cleanly)
   surfaces in PowerShell as **`-1`**, and because output was captured
   (`capture_output=True`) instead of streamed, **stdout comes back empty**.

So `-1 + empty stdout` is the signature of *"the blocked process tree was killed,"*
**not** *"the step produced a bad result."*

**Why it is a *false* artifact.** The real work of every step is deterministic and
**file-based**. Trust the on-disk artifact, not the exit code:

| Step | Verify this artifact |
|------|----------------------|
| 2 | `output/clustering/symbols/cluster_labels.json` — valid JSON, one entry per cluster, correct `layer` values |
| 4 | `intermediate-docs/**/*.content.md` **and** `copilot-docs/L{1,2,3}-*/**/*.md` — real distilled content, each final ≤ `MAX_LINES` |
| 5 | `copilot-docs/L0-foundations/codebase-primer.md` (real sections, not the minimal fallback) + `docs-index.md` |
| 6 | `.github/copilot-instructions*.md` — populated Ownership Table (not the minimal-fallback template) |

Quick confirmation that you are hitting re-entrancy (and not a genuine failure):
run a trivial nested probe — `agency copilot -p "reply PONG" --no-default-mcps`.
If the *"reply PONG"* instruction is delivered back to your current session as a
new turn (instead of a separate agent answering), nested `agency` is not
sandboxed in your environment and the deadlock will occur.

**How to avoid / work around it**

- **Preferred:** run the pipeline (or at least the LLM steps 2/4/5/6) in a
  **plain terminal**, NOT from within an active Copilot/agent session. In a plain
  shell the nested `agency copilot` launches its own isolated agent and each step
  exits `0` normally.
- **When you must run inside an agent session:** do not treat `-1` as fatal.
  Drive each step's *deterministic* Python directly and supply the *LLM-authored*
  content out-of-band (e.g. author the `result_file` the step expects, or hand the
  step's prompt to a separate sub-agent), then re-run so the step consumes the
  pre-filled `result_file` through its own validation/save logic. All step scripts
  read their result from a file, so a correctly-formatted result file makes the
  step succeed regardless of how it was produced. Idempotent steps are safe to
  re-run — completed artifacts are detected and preserved.
- **Never** conclude a step failed from the exit code alone — always check the
  artifact table above first.
