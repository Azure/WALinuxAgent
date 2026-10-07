#!/usr/bin/env python3
"""
run_dag_pipeline.py — Resume-aware orchestrator for the DAG generation pipeline.

Single entry point for the dag-generation skill. It does two things:

  1. BOOTSTRAP — ensures <repo>/scripts/dag-enrichment/ contains every bundled
     pipeline script (copies any that are missing from this script's own
     references/ bundle). This is why the skill can be run with only the
     references present — the working scripts directory is populated on demand.
  2. RESUME — self-identifies how far the pipeline has progressed for THIS repo
     by inspecting each step's output artifacts on disk, then runs ONLY the
     remaining steps. Safe to re-run: completed steps are detected and skipped,
     so an interrupted run (or one done step-by-step by hand) resumes exactly
     where it left off.

Designed to be launched by an AI agent running the skill (the user does not run
the individual step scripts themselves). It works whether invoked from the
bundled references copy or from scripts/dag-enrichment/.

Why artifact-based detection (not just a state file)
----------------------------------------------------
Completion is detected from the actual output files, so progress made by hand
(or by a previous partial run) is always respected. A complementary
``.dag-pipeline-state.json`` audit log is written after each successful step,
but the on-disk artifacts are the source of truth.

Steps (Generation 0-6, Enrichment 7-8)
--------------------------------------
  0 step0_extract_symbols.py            -> output/clustering/symbols/file_metadata.json
  1 step1_namespace_clustering.py       -> output/clustering/symbols/cluster_details.json
  2 step2_label_clusters.py        (LLM)-> output/clustering/symbols/cluster_labels.json
  3 step3_generate_mapping.py           -> compose_to_dag_mapping-symbols.json
  4 create_dags_from_mapping.py    (LLM)-> intermediate-docs/ + copilot-docs/
  5 generate_indexes_and_l0.py     (LLM)-> copilot-docs/docs-index.md + L0-foundations/
  6 step6_generate_copilot_instructions.py (LLM)-> .github/copilot-instructions.md
  7 step7_inject_routing_table.py       -> AUTO-GENERATED-MAPPING block in instructions
  8 step8_inject_tier2_pointer.py       -> TIER2-POINTER banners in copilot-docs/**

Usage
-----
    # From the skill bundle (bootstraps scripts/, then runs remaining steps):
    python .github/skills/dag-generation/references/run_dag_pipeline.py

    # Or, once bootstrapped, from the working location:
    python scripts/dag-enrichment/run_dag_pipeline.py

    # Print the status table + what WOULD run, then exit (also bootstraps):
    python .github/skills/dag-generation/references/run_dag_pipeline.py --status

    # Force a full re-run; re-run from a step; or a single step:
    python scripts/dag-enrichment/run_dag_pipeline.py --force
    python scripts/dag-enrichment/run_dag_pipeline.py --from 4
    python scripts/dag-enrichment/run_dag_pipeline.py --only 8

    # Overwrite stale working scripts from the bundle; pin the repo root:
    python .github/skills/dag-generation/references/run_dag_pipeline.py --sync-scripts
    python .github/skills/dag-generation/references/run_dag_pipeline.py --repo-root /path/to/repo

    # Tuning forwarded to the underlying steps:
    python scripts/dag-enrichment/run_dag_pipeline.py --min-cluster-size 4 --max-parallel 6
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# UTF-8 safety
# ---------------------------------------------------------------------------
# The orchestrator launches this runner via `cmd /c` under the Windows cp1252
# codepage. Step scripts print non-ASCII glyphs (e.g. the "->" arrow in step0's
# namespace table, check/clock marks in step4), which raise UnicodeEncodeError
# under cp1252 and kill the step (repo then fails every attempt). Force UTF-8 for
# THIS process's own streams and export PYTHONUTF8/PYTHONIOENCODING so every step
# subprocess (spawned via subprocess.run, which inherits os.environ) is UTF-8 too.
os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------------------
# Location model
# ---------------------------------------------------------------------------
# This runner is shipped inside the dag-generation skill at
#   .github/skills/dag-generation/references/
# and is ALSO copied into the working location
#   scripts/dag-enrichment/
# It must work when launched from EITHER place. BUNDLE_DIR is wherever this file
# currently lives (and where its sibling step scripts are bundled). The step
# scripts must run from <repo>/scripts/dag-enrichment/ because they compute
# their own repo root as SCRIPT_DIR.parent.parent and write output/ there — so
# the runner BOOTSTRAPS that directory (copies the bundled *.py into it) before
# running anything.
BUNDLE_DIR = Path(__file__).resolve().parent

# A directory is treated as the repo root if it carries any of these markers.
_ROOT_MARKERS = (".git", ".github", "copilot-docs", ".compose", ".astred")

ROUTING_MARKER = "AUTO-GENERATED-MAPPING:BEGIN"
TIER2_MARKER = "TIER2-POINTER:BEGIN"

# These are filled in by set_paths() — first at import (auto-detected), then
# again in main() if --repo-root is supplied.
REPO_ROOT: Path
SCRIPTS_DIR: Path
CLUSTER_DIR: Path
MAPPING_FILE: Path
COPILOT_DOCS: Path
INTERMEDIATE_DOCS: Path
GITHUB_DIR: Path
STATE_FILE: Path


def detect_repo_root(start: Path, override: str | None = None) -> Path:
    """Find the repo root by walking up from the bundle dir, then the CWD."""
    if override:
        return Path(override).resolve()
    for base in (start, Path.cwd().resolve()):
        for d in [base, *base.parents]:
            if any((d / m).exists() for m in _ROOT_MARKERS):
                return d
    return Path.cwd().resolve()


def set_paths(repo_root: Path) -> None:
    """Anchor all artifact paths to the chosen repo root."""
    global REPO_ROOT, SCRIPTS_DIR, CLUSTER_DIR, MAPPING_FILE
    global COPILOT_DOCS, INTERMEDIATE_DOCS, GITHUB_DIR, STATE_FILE
    REPO_ROOT = repo_root
    SCRIPTS_DIR = repo_root / "scripts" / "dag-enrichment"
    CLUSTER_DIR = SCRIPTS_DIR / "output" / "clustering" / "symbols"
    MAPPING_FILE = SCRIPTS_DIR / "compose_to_dag_mapping-symbols.json"
    COPILOT_DOCS = repo_root / "copilot-docs"
    INTERMEDIATE_DOCS = repo_root / "intermediate-docs"
    GITHUB_DIR = repo_root / ".github"
    STATE_FILE = repo_root / ".dag-pipeline-state.json"


def bootstrap_scripts(*, sync_all: bool) -> list[str]:
    """Ensure scripts/dag-enrichment/ holds every bundled pipeline *.py.

    Copies missing scripts (or all, when sync_all) from BUNDLE_DIR into
    SCRIPTS_DIR. No-op when the runner is already executing in place. Returns
    the list of file names that were copied.
    """
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    if BUNDLE_DIR.resolve() == SCRIPTS_DIR.resolve():
        return []  # already running from the working dir
    copied: list[str] = []
    for py in sorted(BUNDLE_DIR.glob("*.py")):
        dest = SCRIPTS_DIR / py.name
        if sync_all or not dest.exists():
            shutil.copy2(py, dest)
            copied.append(py.name)
    return copied


# Initialise with auto-detected paths so the detection helpers work even before
# main() runs (e.g. if imported).
set_paths(detect_repo_root(BUNDLE_DIR))


# ---------------------------------------------------------------------------
# Detection helpers (on-disk artifacts are the source of truth)
# ---------------------------------------------------------------------------
def _nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _has_glob(root: Path, pattern: str, *, exclude_names: tuple[str, ...] = ()) -> bool:
    if not root.is_dir():
        return False
    for p in root.glob(pattern):
        if p.is_file() and p.name not in exclude_names:
            try:
                if p.stat().st_size > 0:
                    return True
            except OSError:
                continue
    return False


def _marker_in_instructions(marker: str) -> bool:
    for name in ("copilot-instructions.md", "copilot-instructions-dag.md"):
        f = GITHUB_DIR / name
        if f.is_file():
            try:
                if marker in f.read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                continue
    return False


def _marker_in_any_copilot_doc(marker: str) -> bool:
    if not COPILOT_DOCS.is_dir():
        return False
    for p in COPILOT_DOCS.rglob("*.md"):
        try:
            if marker in p.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _instructions_exist() -> bool:
    return (GITHUB_DIR / "copilot-instructions.md").is_file() or (
        GITHUB_DIR / "copilot-instructions-dag.md"
    ).is_file()


def _dag_instructions_exist() -> bool:
    # Step 6 runs with --force-suffix, so it always targets copilot-instructions-dag.md.
    # Detection must key ONLY on that file — otherwise a pre-existing hand-authored
    # copilot-instructions.md would make step 6 look "done" and it would never run.
    return (GITHUB_DIR / "copilot-instructions-dag.md").is_file()


def _routing_marker_in_dag() -> bool:
    # Step 7 injects the routing table into copilot-instructions-dag.md, so detection
    # keys on that file only.
    f = GITHUB_DIR / "copilot-instructions-dag.md"
    if not f.is_file():
        return False
    try:
        return ROUTING_MARKER in f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def _done_step4() -> bool:
    # Step 4 is the only producer of intermediate-docs/*.content.md, and it also
    # emits the tier-1 DAG docs under copilot-docs/L{1,2,3}-*/.
    has_intermediate = _has_glob(INTERMEDIATE_DOCS, "**/*.content.md")
    has_final = _has_glob(COPILOT_DOCS, "L*-*/**/*.md", exclude_names=("docs-index.md",))
    return has_intermediate and has_final


def _done_step5() -> bool:
    has_index = _nonempty(COPILOT_DOCS / "docs-index.md")
    has_l0 = _has_glob(COPILOT_DOCS / "L0-foundations", "*.md")
    return has_index and has_l0


# ---------------------------------------------------------------------------
# Step definitions
# ---------------------------------------------------------------------------
class Step:
    def __init__(self, num, script, title, is_llm, detect, args_fn=None):
        self.num = num
        self.script = script
        self.title = title
        self.is_llm = is_llm
        self.detect = detect
        self.args_fn = args_fn or (lambda opts: [])


def build_steps() -> list[Step]:
    return [
        Step(0, "step0_extract_symbols.py", "Extract symbols", False,
             lambda: _nonempty(CLUSTER_DIR / "file_metadata.json")),
        Step(1, "step1_namespace_clustering.py", "Cluster by namespace", False,
             lambda: _nonempty(CLUSTER_DIR / "cluster_details.json"),
             lambda o: (["--min-cluster-size", str(o.min_cluster_size)]
                        if o.min_cluster_size is not None else [])),
        Step(2, "step2_label_clusters.py", "Label clusters", True,
             lambda: _nonempty(CLUSTER_DIR / "cluster_labels.json"),
             lambda o: ["--approach", "symbols"]),
        Step(3, "step3_generate_mapping.py", "Generate mapping JSON", False,
             lambda: _nonempty(MAPPING_FILE),
             lambda o: ["--approach", "symbols"]),
        Step(4, "create_dags_from_mapping.py", "Create DAG docs", True,
             _done_step4,
             lambda o: ["--max-parallel", str(o.max_parallel)]),
        Step(5, "generate_indexes_and_l0.py", "Generate L0 + indexes", True,
             _done_step5),
        Step(6, "step6_generate_copilot_instructions.py", "Generate copilot-instructions", True,
             _dag_instructions_exist,
             lambda o: ["--force-suffix"]),
        Step(7, "step7_inject_routing_table.py", "Inject Component Mapping table", False,
             _routing_marker_in_dag,
             lambda o: ["--instructions", ".github/copilot-instructions-dag.md"]),
        Step(8, "step8_inject_tier2_pointer.py", "Inject tier-2 pointer banners", False,
             lambda: _marker_in_any_copilot_doc(TIER2_MARKER)),
    ]


# ---------------------------------------------------------------------------
# State audit log (complementary to artifact detection)
# ---------------------------------------------------------------------------
def _load_state() -> dict:
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _record_step(num: int, title: str) -> None:
    state = _load_state()
    hist = state.get("step_history", {})
    hist[str(num)] = {
        "title": title,
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    completed = sorted({int(k) for k in hist}, key=int)
    state.update({
        "step_history": hist,
        "completed_steps": completed,
        "last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    try:
        STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass  # audit log is best-effort; artifacts remain the source of truth


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_step(step: Step, opts) -> bool:
    cmd = [sys.executable, str(SCRIPTS_DIR / step.script), *step.args_fn(opts)]
    print(f"\n{'='*64}\nSTEP {step.num}: {step.title}"
          f"{'  (LLM)' if step.is_llm else ''}\n{'='*64}")
    print("  $ " + " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    if result.returncode != 0:
        print(f"\n[X] Step {step.num} failed (exit {result.returncode}).")
        return False
    print(f"\n[OK] Step {step.num} complete.")
    return True


def print_status(steps: list[Step], plan: set[int]) -> None:
    state = _load_state()
    last = state.get("last_run")
    print("=" * 64)
    print("DAG PIPELINE STATUS")
    print("=" * 64)
    print(f"Repo:      {REPO_ROOT}")
    if last:
        print(f"Last run:  {last}")
    print(f"{'Step':<5}{'Status':<10}{'Plan':<10}Title")
    print("-" * 64)
    for s in steps:
        done = s.detect()
        status = "DONE" if done else "pending"
        action = "RUN" if s.num in plan else ("skip" if done else "-")
        llm = "  (LLM)" if s.is_llm else ""
        print(f"{s.num:<5}{status:<10}{action:<10}{s.title}{llm}")
    print("-" * 64)
    if plan:
        ordered = ", ".join(str(n) for n in sorted(plan))
        print(f"Will run steps: {ordered}")
    else:
        print("Nothing to run — pipeline already complete for this repo.")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--status", "--dry-run", dest="status", action="store_true",
                    help="Print the detected status table + plan, then exit (no execution).")
    ap.add_argument("--force", action="store_true",
                    help="Re-run every step from 0, ignoring detection.")
    ap.add_argument("--from", dest="from_step", type=int, default=None, metavar="N",
                    help="Force re-run from step N onward (ignore detection for steps >= N).")
    ap.add_argument("--only", type=int, default=None, metavar="N",
                    help="Run only step N (ignoring detection).")
    ap.add_argument("--min-cluster-size", type=int, default=None,
                    help="Forwarded to step 1 (namespace clustering).")
    ap.add_argument("--max-parallel", type=int, default=4,
                    help="Forwarded to step 4 (DAG creation). Default 4.")
    ap.add_argument("--repo-root", default=None,
                    help="Target repo root. Default: auto-detected from this "
                         "script's location, then the current directory.")
    ap.add_argument("--sync-scripts", action="store_true",
                    help="Overwrite ALL scripts in scripts/dag-enrichment/ from "
                         "the bundled references copy (default: copy missing only).")
    opts = ap.parse_args()

    # Resolve repo root (honour --repo-root override) and re-anchor all paths.
    set_paths(detect_repo_root(BUNDLE_DIR, opts.repo_root))

    # Bootstrap: make sure the working scripts/dag-enrichment/ holds every
    # bundled pipeline script before we try to run any of them. This is what
    # lets the skill be invoked with only the references bundle present.
    copied = bootstrap_scripts(sync_all=opts.sync_scripts)
    if copied:
        verb = "Synced" if opts.sync_scripts else "Copied missing"
        print(f"[bootstrap] {verb} {len(copied)} script(s) into {SCRIPTS_DIR}:")
        for name in copied:
            print(f"             + {name}")
    elif BUNDLE_DIR.resolve() != SCRIPTS_DIR.resolve():
        print(f"[bootstrap] scripts/dag-enrichment/ already complete "
              f"({SCRIPTS_DIR}).")

    steps = build_steps()
    valid = {s.num for s in steps}

    # Decide which steps to run.
    if opts.only is not None:
        if opts.only not in valid:
            print(f"--only {opts.only} is out of range (0-8).")
            return 2
        plan = {opts.only}
    elif opts.force:
        plan = set(valid)
    elif opts.from_step is not None:
        if opts.from_step not in valid:
            print(f"--from {opts.from_step} is out of range (0-8).")
            return 2
        plan = {s.num for s in steps if s.num >= opts.from_step}
    else:
        # Auto-resume: run every step whose artifacts are not present.
        plan = {s.num for s in steps if not s.detect()}

    if opts.status:
        print_status(steps, plan)
        return 0

    print_status(steps, plan)
    if not plan:
        return 0

    for s in steps:
        if s.num not in plan:
            if s.detect():
                print(f"\n[skip] Step {s.num}: {s.title} (already complete)")
            continue
        if not run_step(s, opts):
            print(f"\nPipeline stopped at step {s.num}. "
                  f"Fix the issue and re-run — completed steps will be skipped "
                  f"automatically (or use --from {s.num}).")
            return 1
        _record_step(s.num, s.title)

    print(f"\n{'='*64}\nPIPELINE COMPLETE\n{'='*64}")
    print("Generated/updated artifacts:")
    print(f"  Clustering:        {CLUSTER_DIR}")
    print(f"  Mapping JSON:      {MAPPING_FILE}")
    print(f"  Final DAGs:        {COPILOT_DOCS}")
    print(f"  Intermediate DAGs: {INTERMEDIATE_DOCS}")
    print(f"  Instructions:      {GITHUB_DIR / 'copilot-instructions-dag.md'}")
    print(f"  State audit log:   {STATE_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
